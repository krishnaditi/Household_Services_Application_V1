from flask import Flask, render_template, redirect, flash, url_for, request, session
from models import db, Admin, Customer, ServiceProfessional, Service, ServiceRequest
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import make_response

app = Flask(__name__)

# Configure secret key for session management
app.config['SECRET_KEY'] = '9fb4d257480501774db0e3b11913a6aa'  # Use a secure and unique key in production

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # or another database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all() # Creates the tables based on models

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register/customer', methods=['POST'])
def customer_register():
    """Handles customer registration."""
    name = request.form.get('customer_name')
    username = request.form.get('customer_username')
    email = request.form.get('customer_email')
    phone_number = request.form.get('customer_phone_number')
    password = request.form.get('customer_password')
    
    # Validate form data
    if not password:
        flash("Password is required.", "danger")
        return redirect(url_for('user_register'))
    
    # Check for existing username or email
    if Customer.query.filter((Customer.username == username) | (Customer.email == email)).first():
        flash("Username or email already in use.", "danger")
        return redirect(url_for('user_register'))
    
    # Create and add new Customer
    new_customer = Customer(
        name=name,
        username=username,
        email=email,
        phone_number=phone_number,
        password=generate_password_hash(password)
    )
    db.session.add(new_customer)
    db.session.commit()
    flash("Customer registered successfully!", "success")
    return redirect(url_for('user_login'))  # Assuming this route exists for login

@app.route('/register/professional', methods=['POST'])
def professional_register():
    """Handles service professional registration."""
    name = request.form.get('professional_name')
    username = request.form.get('professional_username')
    email = request.form.get('professional_email')
    service_type = request.form.get('service_type')
    location = request.form.get('location')
    pincode = request.form.get('pincode')
    experience = request.form.get('experience')
    password = request.form.get('professional_password')
    
    # Validate form data
    if not password:
        flash("Password is required.", "danger")
        return redirect(url_for('user_register'))
    
    # Check for existing username or email
    if ServiceProfessional.query.filter((ServiceProfessional.username == username) | (ServiceProfessional.email == email)).first():
        flash("Username or email already in use.", "danger")
        return redirect(url_for('user_register'))

    # Create and add new Service Professional (not approved initially)
    new_professional = ServiceProfessional(
        name=name,
        username=username,
        email=email,
        password=generate_password_hash(password),
        service_type=service_type,
        location=location,
        pincode=pincode,
        experience=experience,
        approved=False
    )
    db.session.add(new_professional)
    db.session.commit()
    flash("Service Professional registered successfully! Awaiting admin approval.", "success")
    return redirect(url_for('user_login'))


@app.route('/register', methods=['GET'])
def user_register():
    """Displays the registration form."""
    return render_template('user_register.html')


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        customer = Customer.query.filter_by(username=username).first()

        if customer:
            # Check if the customer is blocked
            if customer.is_blocked:
                flash("Your account has been blocked. Please contact support.", "danger")
                return redirect(url_for('user_login'))

            # Validate password
            if check_password_hash(customer.password, password):
                session['customer_id'] = customer.id  # Set the session variable for the customer
                flash("Logged in successfully!", "success")
                return redirect(url_for('customer_dashboard'))  # Redirect to customer dashboard

        flash("Invalid username or password", "danger")
        return redirect(url_for('user_login'))

    return render_template('user_login.html')

@app.route('/professional_login', methods=['POST'])
def professional_login():
    username = request.form.get('username')
    password = request.form.get('password')
    professional = ServiceProfessional.query.filter_by(username=username).first()

    if not professional:
        flash("No such professional found.", "danger")
        return redirect(url_for('professional_login'))

    # Check if the professional is blocked
    if professional.is_blocked:
        flash("Your account has been blocked. Please contact support.", "danger")
        return render_template("user_login.html")

    # Check if the professional is approved
    if not professional.approved:
        flash("Your account is pending approval. Please wait for admin approval.", "warning")
        return render_template("user_login.html")

    # Validate password
    if check_password_hash(professional.password, password):
        session.clear()  # Clear previous session
        session['professional_id'] = professional.id
        flash("Welcome to your dashboard!", "success")
        return redirect(url_for('service_professional_dashboard'))

    flash("Invalid username or password.", "danger")
    return redirect(url_for('professional_login'))


@app.route('/service_professional_dashboard')
def service_professional_dashboard():
    professional_id = session.get('professional_id')
    if not professional_id:
        flash("You must be logged in to access this page.", "error")
        return redirect(url_for('professional_login'))

    professional = ServiceProfessional.query.get(professional_id)
    if not professional:
        flash("Professional not found.", "error")
        return redirect(url_for('professional_login'))

    # Fetch assigned service requests
    assigned_requests = ServiceRequest.query.filter_by(professional_id=professional_id).filter(
        ServiceRequest.service_status.in_(["accepted", "closed"])).all()

    # Fetch pending requests matching the professional's service type
    pending_requests = ServiceRequest.query.filter(
        ServiceRequest.service_status == "requested",
        ServiceRequest.professional_id == None,
        ServiceRequest.service.has(name=professional.service_type)
    ).all()

    return render_template(
        'service_professional_dashboard.html',
        professional=professional,
        assigned_requests=assigned_requests,
        pending_requests=pending_requests
    )


@app.route('/customer/dashboard')
def customer_dashboard():
    if 'customer_id' not in session:
        flash("You need to log in first.", "danger")
        return redirect(url_for('user_login'))

    customer = Customer.query.get(session['customer_id'])
    service_requests = customer.service_requests  # Fetch the customer's service requests
    available_services = Service.query.all()  # Fetch all services created by the admin

    return render_template('customer_dashboard.html', 
                           customer=customer, 
                           service_requests=service_requests,
                           available_services=available_services)


@app.route('/service/request', methods=['GET', 'POST'])
def create_service_request():
    if 'customer_id' not in session:
        flash("You need to log in first.", "danger")
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        # Get the form data
        service_type = request.form.get('service_type')
        description = request.form.get('description')

        print(f"Service Type: {service_type}")
        print(f"Description: {description}")

        # Ensure the service exists
        service = Service.query.filter_by(name=service_type).first()
        if not service:
            flash("Service type not found", "danger")
            return redirect(url_for('create_service_request'))

        # Create the service request
        new_request = ServiceRequest(
            service_id=service.id,
            customer_id=session['customer_id'],
            remarks=description,
            service_status="requested"
        )
        
        db.session.add(new_request)
        db.session.commit()

        flash("Service request created successfully!", "success")
        return redirect(url_for('customer_dashboard'))

    return render_template('create_service_request.html')


@app.route('/service/request/<int:request_id>/edit', methods=['GET', 'POST'])
def edit_service_request(request_id):
    request_to_edit = ServiceRequest.query.get_or_404(request_id)

    # Ensure the customer is the owner of the service request
    if request_to_edit.customer_id != session['customer_id']:
        flash("You don't have permission to edit this request.", "danger")
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST':
        request_to_edit.remarks = request.form.get('remarks')
        request_to_edit.service_status = request.form.get('status')

        db.session.commit()

        flash("Service request updated successfully!", "success")
        return redirect(url_for('customer_dashboard'))  # Redirect to the dashboard

    return render_template('edit_service_request.html', request=request_to_edit)

@app.route('/service/request/<int:request_id>/close', methods=['POST'])
def close_service_request(request_id):
    request_to_close = ServiceRequest.query.get_or_404(request_id)

    # Ensure the customer is the owner of the service request
    if request_to_close.customer_id != session['customer_id']:
        flash("You don't have permission to close this request.", "danger")
        return redirect(url_for('customer_dashboard'))

    # Close the service request
    request_to_close.service_status = "closed"
    request_to_close.date_of_completion = datetime.utcnow()

    db.session.commit()

    flash("Service request closed successfully!", "success")
    return redirect(url_for('customer_dashboard'))


# Hardcoded admin credentials
HARD_CODED_ADMIN = {
    "username": "admin",
    "password": "1234"  # Replace with a more secure password
}

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check admin credentials
        if username == HARD_CODED_ADMIN["username"] and password == HARD_CODED_ADMIN["password"]:
            session['admin_logged_in'] = True
            session['admin_logged_in_id'] = 1  # Hard-code or dynamically assign the admin's ID here
            flash("Welcome, Admin!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if admin is logged in
    if not session.get('admin_logged_in'):
        flash("You need to log in as admin to access this page.", "warning")
        return redirect(url_for('admin_login'))
    
    # Fetch the required data
    admin = {"username": HARD_CODED_ADMIN["username"]}
    services = Service.query.all()
    pending_professionals = ServiceProfessional.query.filter_by(approved=False).all()
    approved_professionals = ServiceProfessional.query.filter_by(approved=True).all()
    customers = Customer.query.all()
    
    return render_template(
        'admin_dashboard.html',
        admin=admin,
        services=services,
        pending_professionals=pending_professionals,
        approved_professionals=approved_professionals,
        customers=customers
    )

@app.route('/admin/search', methods=['GET'])
def admin_search():
    # Example hardcoded admin object
    admin = {"username": "admin"}  # Replace with actual data as needed
    
    query = request.args.get('query', '').strip()  # Get the search term from the query parameters
    if not query:
        return render_template(
            'admin_dashboard.html',
            customers=[],
            professionals=[],
            services=[],
            search_query=query,
            admin=admin  # Pass admin to the template
        )

    # Search Customers, Professionals, and Services by name
    customers = Customer.query.filter(Customer.name.ilike(f"%{query}%")).all()
    professionals = ServiceProfessional.query.filter(ServiceProfessional.name.ilike(f"%{query}%")).all()
    services = Service.query.filter(Service.name.ilike(f"%{query}%")).all()

    return render_template(
        'admin_dashboard.html',
        customers=customers,
        professionals=professionals,
        services=services,
        search_query=query,
        admin=admin  # Pass admin to the template
    )

@app.route('/approve_professional/<int:professional_id>', methods=['POST'])
def approve_professional(professional_id):
    professional = ServiceProfessional.query.get_or_404(professional_id)
    professional.approved = True
    db.session.commit()
    flash(f'Service Professional {professional.name} approved successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_professional/<int:professional_id>', methods=['POST'])
def reject_professional(professional_id):
    professional = ServiceProfessional.query.get_or_404(professional_id)
    db.session.delete(professional)
    db.session.commit()
    flash(f'Service Professional {professional.name} rejected.', 'danger')
    return redirect(url_for('admin_dashboard'))


@app.route('/create_service', methods=['GET', 'POST'])
def create_service():
    if request.method == 'POST':
        # Ensure an admin is logged in
        admin_id = session.get('admin_logged_in_id')  # Adjust this key if necessary
        if not admin_id:
            flash("You must be logged in as an admin to create a service.", "danger")
            return redirect(url_for('admin_login'))

        # Retrieve form data
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        time_required = request.form.get('time_required')

        # Create a new service and include the admin_id
        new_service = Service(
            name=name,
            description=description,
            price=price,
            time_required=time_required,
            admin_id=admin_id  # Set the admin_id
        )
        db.session.add(new_service)
        db.session.commit()

        flash("Service created successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('create_service.html')


@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)

    if request.method == 'POST':
        service.name = request.form.get('name')
        service.description = request.form.get('description')
        service.price = request.form.get('price')
        service.time_required = request.form.get('time_required')
        
        db.session.commit()
        flash("Service updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_service.html', service=service)

@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    # Attempt to fetch the service by its ID
    service = Service.query.get_or_404(service_id)
    
    # Perform the delete operation
    db.session.delete(service)
    db.session.commit()
    
    # Provide feedback to the user
    flash(f"Service '{service.name}' deleted successfully.", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route('/view_service_requests')
def view_service_requests():
    # Retrieve service requests to display (this assumes a ServiceRequest model exists)
    service_requests = ServiceRequest.query.all()
    return render_template('view_service_requests.html', service_requests=service_requests)

@app.route('/block_user', methods=['POST'])
def block_user():
    user_id = request.form.get('user_id')
    user_type = request.form.get('user_type')

    if user_type == 'customer':
        user = Customer.query.get(user_id)
    elif user_type == 'professional':
        user = ServiceProfessional.query.get(user_id)
    else:
        flash("Invalid user type specified.", "error")
        return redirect(url_for('admin_dashboard'))

    if user:
        user.is_blocked = True
        db.session.commit()
        flash(f"{user.name} has been blocked.", "success")
    else:
        flash("User not found.", "error")

    return redirect(url_for('admin_dashboard'))

@app.route('/unblock_user', methods=['POST'])
def unblock_user():
    user_id = request.form.get('user_id')
    user_type = request.form.get('user_type')

    if user_type == 'customer':
        user = Customer.query.get(user_id)
    elif user_type == 'professional':
        user = ServiceProfessional.query.get(user_id)
    else:
        flash("Invalid user type specified.", "error")
        return redirect(url_for('admin_dashboard'))

    if user:
        user.is_blocked = False
        db.session.commit()
        flash(f"{user.name} has been unblocked.", "success")
    else:
        flash("User not found.", "error")

    return redirect(url_for('admin_dashboard'))


@app.route('/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    professional_id = session.get('professional_id')
    if not professional_id:
        flash("You must be logged in to accept requests.", "error")
        return redirect(url_for('professional_login'))

    service_request = ServiceRequest.query.get_or_404(request_id)

    # Ensure the request is in "requested" status and not already assigned
    if service_request.service_status != "requested" or service_request.professional_id is not None:
        flash("This request cannot be accepted.", "error")
        return redirect(url_for('service_professional_dashboard'))

    # Assign the request to the logged-in professional
    service_request.professional_id = professional_id
    service_request.service_status = "accepted"
    db.session.commit()

    flash("Service request accepted successfully!", "success")
    return redirect(url_for('service_professional_dashboard'))



@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.service_status != "requested":
        flash("This request cannot be rejected.", "danger")
        return redirect(url_for('service_professional_dashboard'))

    service_request.service_status = "rejected"
    service_request.professional_id = None
    db.session.commit()
    flash("Service request rejected successfully!", "success")
    return redirect(url_for('service_professional_dashboard'))


@app.route('/mark_complete/<int:request_id>', methods=['POST'])
def mark_complete(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.service_status != "accepted":
        flash("Only accepted requests can be marked as complete.", "danger")
        return redirect(url_for('service_professional_dashboard'))

    service_request.service_status = "closed"
    service_request.date_of_completion = datetime.utcnow()
    db.session.commit()
    flash("Service request marked as complete!", "success")
    return redirect(url_for('service_professional_dashboard'))


@app.route('/logout')
def logout():
    # Clear session keys for all user roles
    session.pop('admin_logged_in', None)
    session.pop('customer_id', None)
    session.pop('professional_id', None)

    # Determine which login page to redirect to
    if 'admin_logged_in' in session:
        flash("Logged out successfully.", "info")
        return render_template("admin_login.html")
    elif 'customer_id' in session:
        flash("Logged out successfully.", "info")
        return render_template("user_login.html")
    elif 'professional_id' in session:
        flash("Logged out successfully.", "info")
        return render_template("user_login.html")

    # Default fallback (if no session key exists)
    flash("Logged out successfully.", "info")
    return redirect(url_for('user_login'))



if __name__ == '__main__':
    app.run(debug=True)

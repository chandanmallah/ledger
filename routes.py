import logging
from flask import render_template, url_for, flash, redirect, request, abort, session
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import and_, or_

from app import app, db
from models import User, Ledger, LedgerEntry, Connection
from forms import (LoginForm, UserCreationForm, LedgerForm, LedgerEntryForm, 
                  ConnectionRequestForm, ProfileUpdateForm)


# Helper functions
def is_using_dummy():
    """Check if the currently logged in user is using dummy data view"""
    if current_user.is_authenticated:
        return current_user.using_dummy
    return False

def admin_required(f):
    """Decorator for routes that require admin privileges"""
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


# Auth routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/check-auth')
def check_auth():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from functools import wraps

# Decorator to ensure only admins can access certain routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/change_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_change_password(user_id):
    """Allow admin to change user passwords without knowing current password"""
    
    # Get the user to update
    user = User.query.get_or_404(user_id)
    
    # Get form data
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    new_dummy_password = request.form.get('new_dummy_password')
    confirm_dummy_password = request.form.get('confirm_dummy_password')
    notify_user = request.form.get('notify_user')
    
    # Validation
    if not new_password or not confirm_password or not new_dummy_password or not confirm_dummy_password:
        flash('All password fields are required.', 'danger')
        return redirect(url_for('manage_users'))
    
    if new_password != confirm_password:
        flash('Real passwords do not match.', 'danger')
        return redirect(url_for('manage_users'))
    
    if new_dummy_password != confirm_dummy_password:
        flash('Dummy passwords do not match.', 'danger')
        return redirect(url_for('manage_users'))
    
    if len(new_password) < 6 or len(new_dummy_password) < 6:
        flash('Passwords must be at least 6 characters long.', 'danger')
        return redirect(url_for('manage_users'))
    
    if new_password == new_dummy_password:
        flash('Real and dummy passwords should be different for security.', 'warning')
        return redirect(url_for('manage_users'))
    
    try:
        # Update user passwords
        user.password_hash = generate_password_hash(new_password)
        user.password_hash_dummy = generate_password_hash(new_dummy_password)
        
        # Log the admin action (optional - add to your logging system)
        app.logger.info(f'Admin {current_user.username} changed passwords for user {user.username}')
        
        # Commit changes
        db.session.commit()
        
        # Send notification email if requested
        if notify_user:
            try:
                send_password_change_notification(user)
            except Exception as e:
                app.logger.error(f'Failed to send notification email: {str(e)}')
                flash(f'Passwords updated successfully, but failed to send notification email to {user.email}.', 'warning')
        
        flash(f'Passwords for user "{user.username}" have been updated successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating passwords for user {user.username}: {str(e)}')
        flash('An error occurred while updating passwords. Please try again.', 'danger')
    
    return redirect(url_for('manage_users'))

def send_password_change_notification(user):
    """Send email notification to user about password change"""
    from flask_mail import Message
    
    if not hasattr(app, 'mail'):
        return  # Mail not configured
    
    msg = Message(
        subject='Password Changed by Administrator',
        sender=app.config.get('MAIL_USERNAME'),
        recipients=[user.email]
    )
    
    msg.body = f'''
    Dear {user.username},

    Your account passwords have been changed by an administrator.

    If you did not request this change, please contact your system administrator immediately.

    For security reasons, please log in and verify your access.

    Best regards,
    System Administrator
    '''
    
    msg.html = f'''
    <h3>Password Changed</h3>
    <p>Dear {user.username},</p>
    <p>Your account passwords have been changed by an administrator.</p>
    <p><strong>If you did not request this change, please contact your system administrator immediately.</strong></p>
    <p>For security reasons, please log in and verify your access.</p>
    <p>Best regards,<br>System Administrator</p>
    '''
    
    app.mail.send(msg)

# Optional: Add audit log for password changes
@app.route('/admin/password_change_log')
@login_required
@admin_required
def password_change_log():
    """View log of password changes made by admins"""
    # This would require a separate audit log table
    # Example structure:
    # class PasswordChangeLog(db.Model):
    #     id = db.Column(db.Integer, primary_key=True)
    #     admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #     target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #     timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    #     ip_address = db.Column(db.String(45))
    
    # logs = PasswordChangeLog.query.order_by(PasswordChangeLog.timestamp.desc()).all()
    # return render_template('admin/password_change_log.html', logs=logs)
    pass


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                user.using_dummy = False
                db.session.commit()
                login_user(user)
                flash('Logged in successfully with real data view.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))

            elif check_password_hash(user.password_hash_dummy, form.password.data):
                user.using_dummy = True
                db.session.commit()
                login_user(user)
                flash('Logged in successfully with dummy data view.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))

        flash('Login unsuccessful. Please check username and password.', 'danger')
    
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Admin routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    user_count = User.query.filter_by(is_admin=False).count()
    ledger_count = Ledger.query.count()
    transaction_count = LedgerEntry.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    
    recent_users = User.query.order_by(User.date_created.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                          title='Admin Dashboard',
                          user_count=user_count,
                          ledger_count=ledger_count,
                          transaction_count=transaction_count,
                          active_users=active_users,
                          recent_users=recent_users)


@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    form = UserCreationForm()
    if form.validate_on_submit():
        # Create the new user with both password hashes
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            password_hash_dummy=generate_password_hash(form.dummy_password.data),
            is_admin=False
        )
        db.session.add(new_user)
        db.session.flush()  # Flush to get the user ID
        
        # Create default dummy ledger for the new user
        dummy_ledger = Ledger(
            name="Personal Account",
            description="Default personal account",
            is_dummy=True,
            user_id=new_user.id
        )
        db.session.add(dummy_ledger)
        
        # Create default real ledger for the new user
        real_ledger = Ledger(
            name="Personal Account",
            description="Default personal account",
            is_dummy=False,
            user_id=new_user.id
        )
        db.session.add(real_ledger)
        
        db.session.commit()
        
        flash(f'User account created for {form.username.data}!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/create_user.html', title='Create User', form=form)


@app.route('/admin/manage_users')
@login_required
@admin_required
def manage_users():
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    return render_template('admin/manage_users.html', title='Manage Users', users=users)


@app.route('/admin/toggle_user/<int:user_id>')
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot deactivate admin users.', 'warning')
        return redirect(url_for('manage_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = "activated" if user.is_active else "deactivated"
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('manage_users'))


# User routes
@app.route('/dashboard')
@login_required
def user_dashboard():
    is_dummy = is_using_dummy()
    
    # Get user's ledgers based on current view (real/dummy)
    ledgers = Ledger.query.filter_by(user_id=current_user.id, is_dummy=is_dummy).all()
    
    # Calculate total balance
    total_balance = 0
    for ledger in ledgers:
        for entry in ledger.entries:
            if entry.is_debit:
                total_balance -= entry.amount
            else:
                total_balance += entry.amount
    
    # Get connection requests only in real mode
    if is_dummy:
        pending_requests = []  # No connection requests in dummy mode
    else:
        pending_requests = Connection.query.filter_by(
            connected_user_id=current_user.id, 
            status='pending'
        ).all()
    
    # Get recent transactions
    recent_transactions = LedgerEntry.query.join(Ledger).filter(
        Ledger.user_id == current_user.id,
        Ledger.is_dummy == is_dummy
    ).order_by(LedgerEntry.date.desc()).limit(5).all()
    
    return render_template('user/dashboard.html',
                          title='Dashboard',
                          ledgers=ledgers,
                          total_balance=total_balance,
                          pending_requests=pending_requests,
                          recent_transactions=recent_transactions,
                          is_dummy=is_dummy)


@app.route('/ledger/create', methods=['GET', 'POST'])
@login_required
def create_ledger():
    is_dummy = is_using_dummy()
    form = LedgerForm()
    
    if form.validate_on_submit():
        ledger = Ledger(
            name=form.name.data,
            description=form.description.data,
            is_dummy=is_dummy,
            user_id=current_user.id
        )
        db.session.add(ledger)
        db.session.commit()
        
        flash('Ledger created successfully!', 'success')
        return redirect(url_for('view_ledger', ledger_id=ledger.id))
    
    return render_template('user/ledger.html', 
                          title='Create Ledger',
                          form=form,
                          is_dummy=is_dummy,
                          action="create")


@app.route('/ledger/<int:ledger_id>')
@login_required
def view_ledger(ledger_id):
    is_dummy = is_using_dummy()
    ledger = Ledger.query.get_or_404(ledger_id)
    
    # Security check: Verify user owns this ledger and it matches the current view mode
    if ledger.user_id != current_user.id or ledger.is_dummy != is_dummy:
        abort(403)
    
    # Create form for adding new entries
    form = LedgerEntryForm()
    form.ledger_id.data = ledger_id
    
    # Get user's connections for the selection field
    connections = User.query.join(Connection, or_(
        and_(Connection.user_id == current_user.id, 
             Connection.connected_user_id == User.id),
        and_(Connection.connected_user_id == current_user.id, 
             Connection.user_id == User.id)
    )).filter(
        Connection.status == 'accepted'
    ).all()
    
    form.connected_user.choices = [(0, 'Select a user')] + [(u.id, u.username) for u in connections]
    
    # Calculate total balance
    balance = 0
    for entry in ledger.entries:
        if entry.is_debit:
            balance -= entry.amount
        else:
            balance += entry.amount
    
    return render_template('user/ledger.html',
                          title=f'Ledger: {ledger.name}',
                          ledger=ledger,
                          form=form,
                          balance=balance,
                          is_dummy=is_dummy,
                          action="view")


@app.route('/ledger/<int:ledger_id>/add_entry', methods=['POST'])
@login_required
def add_ledger_entry(ledger_id):
    is_dummy = is_using_dummy()
    ledger = Ledger.query.get_or_404(ledger_id)
    
    # Security check: Verify user owns this ledger and it matches the current view mode
    if ledger.user_id != current_user.id or ledger.is_dummy != is_dummy:
        abort(403)
    
    form = LedgerEntryForm()
    
    # Handle based on view mode (dummy or real)
    if is_dummy:
        # In dummy mode, allow any entry without validation or connections
        is_debit = form.transaction_type.data == 'debit'
        entry = LedgerEntry(
            description=form.description.data,
            amount=form.amount.data,
            is_debit=is_debit,
            ledger_id=ledger_id,
            connected_user_id=None  # No connected user in dummy mode
        )
        db.session.add(entry)
        db.session.commit()
        flash('Dummy ledger entry added successfully!', 'success')
        
    else:
        # Real mode - Get user's connections for the validation
        connections = User.query.join(Connection, or_(
            and_(Connection.user_id == current_user.id, 
                Connection.connected_user_id == User.id),
            and_(Connection.connected_user_id == current_user.id,
                Connection.user_id == User.id)
        )).filter(
            Connection.status == 'accepted'
        ).all()
        connection_user_ids = [u.id for u in connections]
        form.connected_user.choices = [(0, 'Select a user')] + [(u.id, u.username) for u in connections]
        
        if form.validate_on_submit():
            # Validate connected user
            connected_user_id = form.connected_user.data
            if connected_user_id != 0 and connected_user_id not in connection_user_ids:
                flash('Invalid connected user selected.', 'danger')
                return redirect(url_for('view_ledger', ledger_id=ledger_id))
            
            # Create the entry for the current user
            is_debit = form.transaction_type.data == 'debit'
            entry = LedgerEntry(
                description=form.description.data,
                amount=form.amount.data,
                is_debit=is_debit,
                ledger_id=ledger_id,
                connected_user_id=connected_user_id if connected_user_id != 0 else None
            )
            db.session.add(entry)
            db.session.flush()  # Get the entry ID without committing
            
            # If this is connected to another user, create the corresponding entry in their ledger
            if connected_user_id != 0:
                # Find the default ledger for the connected user
                connected_user_ledger = Ledger.query.filter_by(
                    user_id=connected_user_id,
                    is_dummy=is_dummy,
                    name="Personal Account"
                ).first()
                
                if connected_user_ledger:
                    # Create mirror entry with opposite debit/credit status
                    mirror_entry = LedgerEntry(
                        description=f"From {current_user.username}: {form.description.data}",
                        amount=form.amount.data,
                        is_debit=not is_debit,  # Opposite of current entry
                        ledger_id=connected_user_ledger.id,
                        connected_user_id=current_user.id,
                        connected_entry_id=entry.id
                    )
                    db.session.add(mirror_entry)
                    
                    # Link the entries together
                    entry.connected_entry_id = mirror_entry.id
            
            db.session.commit()
            flash('Ledger entry added successfully!', 'success')
            
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('view_ledger', ledger_id=ledger_id))


from sqlalchemy import func

@app.route('/ledger/<int:ledger_id>/users')
@login_required
def get_ledger_users(ledger_id):
    print("in")
    """
    Get all users who have transactions in this ledger
    """
    is_dummy = is_using_dummy()
    
    # Get the ledger and verify ownership
    ledger = Ledger.query.get_or_404(ledger_id)
    if ledger.user_id != current_user.id or ledger.is_dummy != is_dummy:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get all users who have transactions in this ledger
    users_with_transactions = db.session.query(User, func.count(LedgerEntry.id).label('transaction_count')).join(
        LedgerEntry, LedgerEntry.connected_user_id == User.id
    ).filter(
        LedgerEntry.ledger_id == ledger_id
    ).group_by(User.id).all()
    
    users_data = []
    for user, transaction_count in users_with_transactions:
        # Calculate balance for this user in this ledger
        entries = LedgerEntry.query.filter_by(
            ledger_id=ledger_id,
            connected_user_id=user.id
        ).all()
        
        balance = 0
        for entry in entries:
            if entry.is_debit:
                balance -= entry.amount
            else:
                balance += entry.amount
        
        users_data.append({
            'id': user.id,
            'username': user.username,
            'transaction_count': transaction_count,
            'balance': float(balance),
            'balance_status': (
                'owed_to_you' if balance > 0 
                else 'you_owe' if balance < 0 
                else 'settled'
            )
        })
    
    # Sort by username
    users_data.sort(key=lambda x: x['username'])
    
    return jsonify({
        'success': True,
        'ledger': {
            'id': ledger.id,
            'name': ledger.name
        },
        'users': users_data,
        'total_users': len(users_data)
    })

#search user in ledger
from flask import jsonify

@app.route('/ledger/<int:ledger_id>/search')
@login_required
def search_ledger_transactions(ledger_id):
    """Search for transactions by username and/or date range with balance calculation"""
    try:
        from datetime import datetime
        
        # Get the ledger and verify ownership
        ledger = Ledger.query.filter_by(id=ledger_id, user_id=current_user.id).first()
        if not ledger:
            return jsonify({'success': False, 'error': 'Ledger not found'}), 404
        
        # Get search parameters
        username = request.args.get('username', '').strip()
        from_date = request.args.get('from_date', '').strip()
        to_date = request.args.get('to_date', '').strip()
        
        # Validate that at least one filter is provided
        if not username and not from_date and not to_date:
            return jsonify({'success': False, 'error': 'At least one filter parameter is required'}), 400
        
        # Parse dates if provided
        from_datetime = None
        to_datetime = None
        
        if from_date:
            try:
                from_datetime = datetime.strptime(from_date, '%Y-%m-%d')
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid from_date format. Use YYYY-MM-DD'}), 400
        
        if to_date:
            try:
                # Add 23:59:59 to include the entire day
                to_datetime = datetime.strptime(to_date + ' 23:59:59', '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid to_date format. Use YYYY-MM-DD'}), 400
        
        # Build base query for transactions in this ledger
        base_query = LedgerEntry.query.filter_by(ledger_id=ledger_id)
        
        # Apply date filters
        if from_datetime:
            base_query = base_query.filter(LedgerEntry.date >= from_datetime)
        if to_datetime:
            base_query = base_query.filter(LedgerEntry.date <= to_datetime)
        
        if username:
            # Search with username filter
            matching_users = User.query.filter(
                User.username.ilike(f'%{username}%')
            ).all()
            
            if not matching_users:
                return jsonify({
                    'success': True,
                    'results': [],
                    'total_balance': 0,
                    'total_transactions': 0
                })
            
            results = []
            total_balance = 0
            
            for user in matching_users:
                # Get transactions for this user with date filters applied
                user_transactions = base_query.filter_by(
                    connected_user_id=user.id
                ).order_by(LedgerEntry.date.desc()).all()
                
                if user_transactions:  # Only include users who have transactions
                    user_balance = 0
                    transaction_list = []
                    
                    for transaction in user_transactions:
                        # Calculate user balance
                        if transaction.is_debit:
                            user_balance -= transaction.amount
                            total_balance -= transaction.amount
                        else:
                            user_balance += transaction.amount
                            total_balance += transaction.amount
                        
                        # Format transaction for response
                        transaction_list.append({
                            'id': transaction.id,
                            'description': transaction.description,
                            'amount': float(transaction.amount),
                            'is_debit': transaction.is_debit,
                            'created_at': transaction.date.isoformat()
                        })
                    
                    results.append({
                        'user': {
                            'id': user.id,
                            'username': user.username
                        },
                        'transactions': transaction_list,
                        'transaction_count': len(user_transactions),
                        'user_balance': round(user_balance, 2)
                    })
            
            total_transactions = sum(len(result['transactions']) for result in results)
            
            return jsonify({
                'success': True,
                'results': results,
                'total_balance': round(total_balance, 2),
                'total_transactions': total_transactions,
                'filters': {
                    'username': username,
                    'from_date': from_date,
                    'to_date': to_date
                }
            })
        
        else:
            # Only date filter (no username filter)
            transactions = base_query.order_by(LedgerEntry.date.desc()).all()
            
            if not transactions:
                return jsonify({
                    'success': True,
                    'transactions': [],
                    'total_balance': 0,
                    'total_transactions': 0
                })
            
            total_balance = 0
            transaction_list = []
            
            for transaction in transactions:
                # Calculate balance
                if transaction.is_debit:
                    total_balance -= transaction.amount
                else:
                    total_balance += transaction.amount
                
                # Get connected user info if exists
                connected_user = None
                if transaction.connected_user_id:
                    connected_user = {
                        'id': transaction.connected_user.id,
                        'username': transaction.connected_user.username
                    }
                
                # Format transaction for response
                transaction_list.append({
                    'id': transaction.id,
                    'description': transaction.description,
                    'amount': float(transaction.amount),
                    'is_debit': transaction.is_debit,
                    'created_at': transaction.date.isoformat(),
                    'connected_user': connected_user
                })
            
            return jsonify({
                'success': True,
                'transactions': transaction_list,
                'total_balance': round(total_balance, 2),
                'total_transactions': len(transactions),
                'filters': {
                    'from_date': from_date,
                    'to_date': to_date
                }
            })
        
    except Exception as e:
        print(f"Search error: {str(e)}")  # For debugging
        return jsonify({'success': False, 'error': 'An error occurred during search'}), 500

@app.route('/connections')
@login_required
def manage_connections():
    is_dummy = is_using_dummy()
    
    # If user is in dummy mode, redirect to dashboard
    if is_dummy:
        flash('Connection features are only available in real data view.', 'info')
        return redirect(url_for('user_dashboard'))
    
    # Get accepted connections
    accepted_connections = Connection.query.filter(
        or_(
            and_(Connection.user_id == current_user.id, Connection.status == 'accepted'),
            and_(Connection.connected_user_id == current_user.id, Connection.status == 'accepted')
        )
    ).all()
    
    # Get pending sent requests
    sent_requests = Connection.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).all()
    
    # Get pending received requests
    received_requests = Connection.query.filter_by(
        connected_user_id=current_user.id,
        status='pending'
    ).all()
    
    # Get all available users that are not the current user and not already connected or requested
    connected_user_ids = []
    
    # Add IDs from accepted connections
    for conn in accepted_connections:
        if conn.user_id == current_user.id:
            connected_user_ids.append(conn.connected_user_id)
        else:
            connected_user_ids.append(conn.user_id)
    
    # Add IDs from sent requests
    for req in sent_requests:
        connected_user_ids.append(req.connected_user_id)
    
    # Add IDs from received requests
    for req in received_requests:
        connected_user_ids.append(req.user_id)
    
    # Query available users (excluding already connected/requested, self, and admin users)
    available_users = User.query.filter(
        and_(
            User.id != current_user.id,
            ~User.id.in_(connected_user_ids),
            User.is_active == True,
            User.is_admin == False  # Exclude admin accounts
        )
    ).all()
    
    form = ConnectionRequestForm()
    
    return render_template('user/connections.html',
                          title='Manage Connections',
                          accepted_connections=accepted_connections,
                          sent_requests=sent_requests,
                          received_requests=received_requests,
                          available_users=available_users,
                          form=form,
                          is_dummy=is_dummy)


@app.route('/connections/request', methods=['POST'])
@login_required
def request_connection():
    # If user is in dummy mode, redirect to dashboard
    is_dummy = is_using_dummy()
    if is_dummy:
        flash('Connection features are only available in real data view.', 'info')
        return redirect(url_for('user_dashboard'))
        
    form = ConnectionRequestForm()
    
    if form.validate_on_submit():
        username = form.username.data
        requested_user = User.query.filter_by(username=username).first()
        
        if not requested_user:
            flash('User not found.', 'danger')
            return redirect(url_for('manage_connections'))
        
        if requested_user.id == current_user.id:
            flash('You cannot connect with yourself.', 'danger')
            return redirect(url_for('manage_connections'))
            
        # Don't allow connections to admin users for security
        if requested_user.is_admin:
            flash('This user is not available for connections.', 'danger')
            return redirect(url_for('manage_connections'))
        
        # Check if connection already exists
        existing_connection = Connection.query.filter(
            or_(
                and_(Connection.user_id == current_user.id, Connection.connected_user_id == requested_user.id),
                and_(Connection.user_id == requested_user.id, Connection.connected_user_id == current_user.id)
            )
        ).first()
        
        if existing_connection:
            if existing_connection.status == 'accepted':
                flash('You are already connected with this user.', 'info')
            elif existing_connection.status == 'pending':
                flash('A connection request with this user is already pending.', 'info')
            else:
                flash('A connection with this user already exists.', 'info')
            return redirect(url_for('manage_connections'))
        
        # Create new connection request
        connection = Connection(
            user_id=current_user.id,
            connected_user_id=requested_user.id,
            status='pending'
        )
        db.session.add(connection)
        db.session.commit()
        
        flash(f'Connection request sent to {requested_user.username}.', 'success')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('manage_connections'))


@app.route('/connections/<int:connection_id>/<action>')
@login_required
def handle_connection(connection_id, action):
    connection = Connection.query.get_or_404(connection_id)
    
    # Verify the current user is involved in this connection
    if connection.user_id != current_user.id and connection.connected_user_id != current_user.id:
        abort(403)
    
    if action == 'accept':
        # Only the request recipient can accept
        if connection.connected_user_id == current_user.id and connection.status == 'pending':
            connection.status = 'accepted'
            db.session.commit()
            flash('Connection request accepted.', 'success')
        else:
            flash('Cannot accept this connection request.', 'danger')
    
    elif action == 'reject':
        # Only the request recipient can reject
        if connection.connected_user_id == current_user.id and connection.status == 'pending':
            connection.status = 'rejected'
            db.session.commit()
            flash('Connection request rejected.', 'success')
        else:
            flash('Cannot reject this connection request.', 'danger')
    
    elif action == 'cancel':
        # Only the request sender can cancel
        if connection.user_id == current_user.id and connection.status == 'pending':
            db.session.delete(connection)
            db.session.commit()
            flash('Connection request canceled.', 'success')
        else:
            flash('Cannot cancel this connection request.', 'danger')
    
    elif action == 'remove':
        # Either user can remove an accepted connection
        if connection.status == 'accepted' and (connection.user_id == current_user.id or 
                                               connection.connected_user_id == current_user.id):
            db.session.delete(connection)
            db.session.commit()
            flash('Connection removed.', 'success')
        else:
            flash('Cannot remove this connection.', 'danger')
    
    return redirect(url_for('manage_connections'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileUpdateForm()
    
    if form.validate_on_submit():
        # Verify current password
        if not check_password_hash(current_user.password_hash, form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('profile'))
        
        # Update email
        current_user.email = form.email.data
        
        # Update passwords if provided
        if form.new_password.data:
            current_user.password_hash = generate_password_hash(form.new_password.data)
        
        if form.new_dummy_password.data:
            current_user.password_hash_dummy = generate_password_hash(form.new_dummy_password.data)
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    
    elif request.method == 'GET':
        form.email.data = current_user.email
    
    is_dummy = is_using_dummy()
    return render_template('user/profile.html', title='Profile', form=form, is_dummy=is_dummy)


# Error handlers
@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html', error_code=404, message='Page not found'), 404


@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', error_code=403, message='Access forbidden'), 403


@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error_code=500, message='Server error'), 500

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, FloatField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User
from wtforms.validators import DataRequired, Length, Optional


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class UserCreationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Real Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Real Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    dummy_password = PasswordField('Dummy Password', validators=[DataRequired(), Length(min=8)])
    confirm_dummy_password = PasswordField('Confirm Dummy Password', 
                                          validators=[DataRequired(), EqualTo('dummy_password')])
    submit = SubmitField('Create User')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please choose a different one.')
            
    def validate_dummy_password(self, dummy_password):
        if dummy_password.data == self.password.data:
            raise ValidationError('Real and dummy passwords must be different for security purposes.')


class LedgerForm(FlaskForm):
    name = StringField('Ledger Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    submit = SubmitField('Create Ledger')


# class LedgerEntryForm(FlaskForm):
#     description = StringField('Description', validators=[DataRequired(), Length(max=200)])
#     amount = FloatField('Amount', validators=[DataRequired()])
#     transaction_type = SelectField('Transaction Type', choices=[
#         ('debit', 'Debit (money leaving your account)'),
#         ('credit', 'Credit (money coming into your account)')
#     ], default='debit')
#     connected_user = SelectField('Connected User', validators=[DataRequired()], coerce=int)
#     ledger_id = HiddenField('Ledger ID')
#     submit = SubmitField('Add Entry')

class LedgerEntryForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired(), Length(max=200)])
    amount = FloatField('Amount', validators=[DataRequired()])
    transaction_type = SelectField('Transaction Type', choices=[
        ('debit', 'Debit (money leaving your account)'),
        ('credit', 'Credit (money coming into your account)')
    ], default='debit')
    
    # CHANGE: Use Optional() instead of DataRequired()
    # This allows the form to validate even when connected_user is 0
    connected_user = SelectField('Connected User', validators=[Optional()], coerce=int)
    
    ledger_id = HiddenField('Ledger ID')
    submit = SubmitField('Add Entry')


class ConnectionRequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=64)])
    submit = SubmitField('Send Connection Request')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if not user:
            raise ValidationError('Username not found. Please check and try again.')


class ProfileUpdateForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password')
    confirm_new_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password')])
    new_dummy_password = PasswordField('New Dummy Password')
    confirm_new_dummy_password = PasswordField('Confirm New Dummy Password', validators=[EqualTo('new_dummy_password')])
    submit = SubmitField('Update Profile')

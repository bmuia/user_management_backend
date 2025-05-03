from .models import UserLog




def log_user_action(user, action, request=None):
    """
    Log a user action in the UserLog model, including optional request info.
    
    :param user: The user performing the action.
    :param action: Description of the action.
    :param request: Django request object (optional).
    """
 

    UserLog.objects.create(
        user=user if user.is_authenticated else None,
        email_snapshot=user.email,
        action=action
    )

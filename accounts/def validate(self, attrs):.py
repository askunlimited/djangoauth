def validate(self, attrs):
    try:
      token = attrs.get('token')
      uidb64 = attrs.get('uidb64')
      password = attrs.get('password')
      confirm_password = attrs.get('confirm_password')
      
      if password != confirm_password:
        raise AuthenticationFailed("passwords do not match")
      
      user_id = force_str(urlsafe_base64_decode(uidb64))
      user = User.objects.get(id=user_id)
      
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise AuthenticationFailed("reset link is invalid or has expired", 401)
      
      user.set_password(password)
      user.save()
      return user
    except Exception as e:
      return AuthenticationFailed("reset link is invalid or has expired")
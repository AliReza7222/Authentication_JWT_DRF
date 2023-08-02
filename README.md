# Authentication_JWT_DRF
<br>
<p>Authentication based on Json Web Token or synonym JWT.</p>
<p>In this repository I tried to create a jwt based authentication with django rest framework or DRF .</p>
<br>
<h2>Install packages</h2>
<p>Install packages in requirement.txt</p>
<pre>command :
  pip install -r requirement.txt
</pre>
<br>
<h2>Custom User</h2>
<p>First i created a Custom model User for register User and config in settings with AUTH_USER_MODEL .</p>
<br>
<h2>Login</h2>
<p>Second stage User must log in for continue in site so send request to endpoint or url '/api/accounts/login/' and enter email and password valid .</p>
<p>Then with package djangorestframework-simplejwt create a jwt token contains refresh token and access token .</p>
<p>These tokens contain a LifeTime that is set in the settings in the SIMPLE_JWT variable. </p>
<br>
<h2>Change Password</h2>
<p>Authentication Default RestFramework changed to JWTAuthentication in settings in variable REST_FRAMEWORK .</p>
<p>For Change Password User you must login Before, so i used Permission IsAuthenticated in this View.</p>
<p>IsAuthenticated checks the header for an access token, returning an error if invalid.</p>
<p>if validated everything's your password successfully changed and in this view used method PUT .</p>
<hr>
<br>

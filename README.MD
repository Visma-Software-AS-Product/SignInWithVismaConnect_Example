# SignIn with Visma Connect - example application - Python Flask

## Introduction
This small application showcases how you could implement SignIn with Visma Connect in your application.
The application is written in Python using the Flask-framework.
For the OAuth/OpenId implementation we have used the Authlib-package (https://docs.authlib.org/en/latest/)

## Requirements
* To be able to use SignIn with Visma Connect you must create an application in the Visma Developer Portal (https://oauth.developers.visma.com).
  * The application must support the authorization code-flow.
  * This will give you a ClientId and ClientSecret, you will also find documentation for Visma Connect here.
* The required python-packages can be installed by running pip install -r requirements.txt

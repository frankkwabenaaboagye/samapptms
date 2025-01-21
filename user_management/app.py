import json
import boto3
import os
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cognito = boto3.client('cognito-idp')
sfn = boto3.client('stepfunctions')
logs = boto3.client('logs')
sns = boto3.client('sns')

myHeaders = {
    'Access-Control-Allow-Headers': 'X-Forwarded-For,Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,access-control-allow-origin,access-control-allow-credentials',
    'Access-Control-Allow-Origin': 'https://main.d3p2bymp0gir41.amplifyapp.com',
    'Access-Control-Allow-Methods': 'POST, GET, PUT, OPTIONS, DELETE',
    'Access-Control-Allow-Credentials': 'true'
}

def lambda_handler(event, context):
    """Sample pure Lambda function

    Parameters
    ----------
    event: dict, required
        API Gateway Lambda Proxy Input Format

        Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format

    context: object, required
        Lambda Context runtime methods and attributes

        Context doc: https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html

    Returns
    ------
    API Gateway Lambda Proxy Output Format: dict

        Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """

    # try:
    #     ip = requests.get("http://checkip.amazonaws.com/")
    # except requests.RequestException as e:
    #     # Send some context about this error to Lambda Logs
    #     print(e)

    #     raise e

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "hello user management is working",
            # "location": ip.text.replace("\n", "")
        }),
    }


def custom_message(event, context):
    logger.info(f"Event received: {event}")  # Add logging
    
    # Handle different trigger sources
    if event['triggerSource'] in ['CustomMessage_AdminCreateUser', 'CustomMessage_ResendCode']:
        try:
            # Get user attributes
            user_name = event['request']['userAttributes'].get('name', 'User')
            temp_password = event['request']['codeParameter']
            
            # Customize your email message
            custom_message = f"""
Hello {user_name},

Welcome to our Task Management System! Your account has been created.

Your temporary login credentials are:
Username: {event['request']['usernameParameter']}
Temporary Password: {temp_password}

Please login at our application and change your password on first sign in.

Log in link = https://main.d3p2bymp0gir41.amplifyapp.com

Best regards,
TMS Team
            """
            
            # Set the custom message
            event['response']['emailMessage'] = custom_message
            event['response']['emailSubject'] = "Welcome to TMS - Your Account Details"
            
            logger.info("Custom message set successfully")
        except Exception as e:
            logger.error(f"Error in custom_message: {str(e)}")
            raise e
    
    return event



def onboard_user(event, context):
    try:
        body = json.loads(event['body'])
        email = body['email']
        name = body['name']
        role = body['role']
              
        USER_POOL_ID = os.environ['USER_POOL_ID']
        
        # Create user in Cognito
        # Create user in Cognito with custom message configuration
        response = cognito.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=email,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'name', 'Value': name},
                {'Name': 'custom:role', 'Value': role}
            ],
            DesiredDeliveryMediums=['EMAIL']
        )
        
        # Add user to appropriate group
        group_name = 'Admin' if role.lower() == 'admin' else 'TeamMember'
        cognito.admin_add_user_to_group(
            UserPoolId=USER_POOL_ID,
            Username=email,
            GroupName=group_name
        )

        try:
            # Start the parallel state machine 
            response = sfn.start_execution(
                stateMachineArn=os.environ['SUBSCRIPTION_WORKFLOW_ARN'],
                input=json.dumps({
                    'email': email,
                    'role': group_name
                })
            )
            print(f"Successfully started subscription workflow: {response['executionArn']}")
        
        except Exception as e:
            print(f"Error starting subscription workflow: {str(e)}")
        
        return {
            "statusCode": 200,
            "headers": myHeaders,
            'body': json.dumps({'message': 'User created successfully'})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": myHeaders,
            "body": json.dumps({'error': str(e)})
        }
    
def get_the_users(event, context):
    print("starting the get users")
    print("event =>")
    print(event)
    try:

        USER_POOL_ID = os.environ['USER_POOL_ID']

        # List users from Cognito User Pool
        response = cognito.list_users(
            UserPoolId=USER_POOL_ID
        )

        print("response...=>")
        print(response)
        
        # Format the response
        users = []
        for user in response.get('Users', []):
            user_data = {
                'id': user['Username'],
                'name': '',
                'email': '',
                'role': '',
                'status': user['UserStatus']
            }
            
            # Extract attributes
            for attr in user.get('Attributes', []):
                if attr['Name'] == 'email':
                    user_data['email'] = attr['Value']
                elif attr['Name'] == 'name':
                    user_data['name'] = attr['Value']
                elif attr['Name'] == 'custom:role':
                    user_data['role'] = attr['Value']
            
            users.append(user_data)
        
        return {
            "statusCode": 200,
            "headers": myHeaders,
            "body": json.dumps({'users': users})
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")  # Add logging for debugging
        return {
            "statusCode": 500,
            "headers": myHeaders,
            "body": json.dumps({
                'error': str(e)
            })
        }
    

def make_sure_role_exists(user_pool_id, username):
        

        #----------------------
    try:

        user_response = cognito.admin_get_user(
            UserPoolId=user_pool_id,
            Username=username
        )

        current_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}

        # Check if all required attributes exist and custom:role is TeamMember
        if ('email' not in current_attributes or 
            'name' not in current_attributes or 
            'custom:role' not in current_attributes or 
            current_attributes['custom:role'] != 'TeamMember'):
            
            # Prepare attributes update maintaining email and name if they exist
            update_attributes = [
                {'Name': 'email', 'Value': current_attributes.get('email', username)},
                {'Name': 'name', 'Value': current_attributes.get('name', username)},
                {'Name': 'custom:role', 'Value': 'TeamMember'}
            ]
            
            print(f"Updating user attributes for {username}")
            cognito.admin_update_user_attributes(
                UserPoolId=user_pool_id,
                Username=username,
                UserAttributes=update_attributes
            )
            print(f"Successfully updated attributes for user {username}")
    except Exception as e:
        print(f"Error in make_sure_role_exists: {str(e)}")
    
def post_confirmation_handler(event, context):
    """
    Handles post confirmation tasks:
    1. Adds user to TeamMember group
    2. Starts subscription workflow
    """
    try:
        # Part 1: Add user to TeamMember group
        user_pool_id = event['userPoolId']
        username = event['userName']

        #--------------to make sure role is set
        make_sure_role_exists(user_pool_id, username)

        
        print("Starting part 1: Adding user to TeamMember group")
        # this part has been done remove it
        cognito.admin_add_user_to_group(
            UserPoolId=user_pool_id,
            Username=username,
            GroupName='TeamMember'
        )

    
        print(f"Successfully added user {username} to TeamMember group")

        # Part 2: Start subscription workflow
        print("Starting part 2: Initiating subscription workflow")
        user_email = event['request']['userAttributes']['email']
        
        # Start the parallel state machine with the email
        response = sfn.start_execution(
            stateMachineArn=os.environ['SUBSCRIPTION_WORKFLOW_ARN'],
            input=json.dumps({
                'email': user_email,
                'role': 'TeamMember'
            })
        )
        print(f"Successfully started subscription workflow: {response['executionArn']}")
        
        return event
        
    except Exception as e:
        print(f"Error in post confirmation handler: {str(e)}")
        raise e
    

def ensure_log_group_exists(context):
    """Ensures CloudWatch log group exists"""
    log_group_name = f"/aws/lambda/{context.function_name}"
    try:
        try:
            logs.create_log_group(logGroupName=log_group_name)
            logger.info(f"Created log group: {log_group_name}")
            logs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=30
            )
        except logs.exceptions.ResourceAlreadyExistsException:
            logger.info(f"Log group already exists: {log_group_name}")
        except Exception as e:
            logger.error(f"Error creating log group: {str(e)}")
    except Exception as e:
        logger.error(f"Error in ensure_log_group_exists: {str(e)}")

def subscribe_the_user(event, context):
    """
    Handles single topic subscription.
    Expected event format:
    {
        "TopicArn": "arn:aws:sns:region:account:topic",
        "Protocol": "email",
        "Endpoint": "user@example.com"
    }
    """
    print("executing handler...")
    ensure_log_group_exists(context)
    logger.info(f"Processing subscription request: {json.dumps(event)}")
    
    try:
        # Extract parameters from the event
        topic_arn = event['TopicArn']
        protocol = event['Protocol']
        endpoint = event['Endpoint']
        role = event.get('Role', 'TeamMember') # Default to teammember if not specified
        
        logger.info(f"Subscribing {endpoint} to topic {topic_arn}")
        
        # Create the subscription
        response = sns.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint,
            ReturnSubscriptionArn=True
        )
        
        subscription_arn = response['SubscriptionArn']

        # Handle admin subscriptions
        if role.lower() == 'admin' and topic_arn.endswith(('ClosedTasksNotificationTopic', 'TasksCompletionNotificationTopic')):
            logger.info("Setting up admin filter policy")
            sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName='FilterPolicy',
                AttributeValue=json.dumps({'responsibility': ['admin']})
            )

        # If this is the assignment notification topic, set up filtering
        # Handle teammember subscriptions
        elif role.lower() == 'teammember':
            logger.info("Setting up TeamMember filter policy")
            sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName='FilterPolicy',
                AttributeValue=json.dumps({'responsibility': [endpoint]})  # Filter by user's email
            )
        
        return {
            'statusCode': 200,
            'body': {
                'message': 'Successfully created subscription',
                'subscriptionArn': subscription_arn,
                'endpoint': endpoint,
                'topicArn': topic_arn
            }
        }
        
    except Exception as e:
        logger.error(f"Error creating subscription: {str(e)}")
        raise e


   


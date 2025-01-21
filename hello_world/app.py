import json
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import uuid
from datetime import datetime, timedelta, timezone
import logging

def assignDynamodb():
    try:
        return boto3.resource('dynamodb')
    except Exception as e:
        return " "
   
def assignTable():
    try:
        return dynamodb.Table(os.environ['TASKS_TABLE'])
    except Exception as e:
        return " "
     
def assignSNS():
    try:
        return boto3.client('sns')
    except Exception as e:
        return " "

def assignSQS():
    try:
        return boto3.client('sqs')
    except Exception as e:
        return " "

def assignStepFnx():
    try:
        return boto3.client('stepfunctions')
    except Exception as e:
        return " "    

dynamodb = assignDynamodb()
table = assignTable()
sns = assignSNS()
sqs = assignSQS()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
stepfunctions = assignStepFnx()


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
            "message": "hello world",
            # "location": ip.text.replace("\n", "")
        }),
    }


def get_the_task(event, context):
    
    # TODO: implement logic for only admin to be able to access this

    try:
        response = table.scan()
        tasks = response.get('Items', [])
        
        return {
            "statusCode": 200,
            "headers": myHeaders,
            "body": json.dumps({
                'message': 'Success',
                'tasks': tasks
            })
        }
    except Exception as e:
        print("error when making the request")
        # logger.error(f"Error retrieving tasks: {str(e)}")
        return {
            "statusCode": 500,
            "headers": myHeaders,
            'body': json.dumps({'error': str(e)})
        }


def create_the_task(event, context):

    print("Event for the create ...")
    print(event)
    print("proeceeding to perform create task...")

    #TODO: implement logic for only admin to create the task

    try:
        body = json.loads(event['body'])
        task_id = str(uuid.uuid4())
        
        task = {
            'task_id': task_id,
            'name': body['name'],
            'description': body['description'],
            'status': 'open', # open by default
            'deadline': body['deadline'],
            'responsibility': body['responsibility'],
            'created_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            'user_comment': '',
            'completed_at': ''
        }

        # Store task in DynamoDB
        table.put_item(Item=task)

        # Send task to SQS for processing
        sqs.send_message(
            QueueUrl=os.environ['TASK_QUEUE_URL'],
            MessageBody=json.dumps(task)
        )

        # Publish to SNS topic with filtering - Redundant
        
        # sns_response = sns.publish(
        #     TopicArn=os.environ['ASSIGNMENT_TOPIC_ARN'],
        #     Message=json.dumps({
        #         'default': json.dumps(task),
        #         'email': f"New task assigned: {task['name']}\nDescription: {task['description']}\nDeadline: {task['deadline']}"
        #     }),
        #     MessageStructure='json',
        #     MessageAttributes={
        #         'responsibility': {
        #             'DataType': 'String',
        #             'StringValue': task['responsibility']
        #         }
        #     }
        # )

        # print("response from sns = ")
        # print(sns_response)
        
        return {
            "statusCode": 200,
            "headers": myHeaders,
            "body": json.dumps({
                'message': 'Success',
                'task': task
            })
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": myHeaders,
            "body": json.dumps({'error': str(e)})
        }


def notify_task_completion(task, completed_by):
    message = {
        'default': json.dumps({
            'task_id': task['task_id'],
            'task_name': task['name'],
            'completed_by': completed_by,
            'completion_time': datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        }),
        'email': f"""
                Task Completed

                Task: {task['name']}
                Completed By: {completed_by}
                Completion Time: {datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}

                Description: {task['description']}
                Original Deadline: {task['deadline']}
                """
    }
    
    # Notify administrators
    sns_response = sns.publish(
        TopicArn=os.environ['TASK_COMPLETION_TOPIC'],
        Message=json.dumps(message),
        MessageStructure='json',
        MessageAttributes={
            'responsibility': {
                'DataType': 'String',
                'StringValue': 'admin'
            }
        }
    )

    logger.info("admin notifed!! ...")
    #logger.info(f"admin notified .. sns response is =>: {json.dumps(sns_response)}")


def update_the_task(event, context):
    logger.info("Event for the update ...")
    logger.info(f"Event: {json.dumps(event)}")

    try:
        # Get task ID from path parameters
        task_id = event['pathParameters']['taskId']
        
        # Get user information from Cognito authorizer
        user_email = event['requestContext']['authorizer']['claims']['email']
        user_groups = event['requestContext']['authorizer']['claims'].get('cognito:groups', [])
        
        # Parse request body
        body = json.loads(event['body'])
        
        # Verify only status and comment are being updated
        allowed_fields = {'status', 'user_comment'}
        update_fields = set(body.keys())
        
        if not update_fields.issubset(allowed_fields):
            return {
                'statusCode': 400,
                'headers': myHeaders,
                'body': json.dumps({
                    'error': 'Only status and user_comment can be updated'
                })
            }
        
        # Get the current task
        task_response = table.get_item(
            Key={'task_id': task_id}
        )
        
        if 'Item' not in task_response:
            return {
                'statusCode': 404,
                'headers': myHeaders,
                'body': json.dumps({'error': 'Task not found'})
            }
            
        current_task = task_response['Item']
        
        # Check if user is authorized (admin or assigned team member)
        if 'Admin' not in user_groups and current_task['responsibility'] != user_email:
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Not authorized to update this task'})
            }
        
        # Prepare update expression
        update_expr = 'SET '
        expr_attrs = {}
        expr_values = {}
        
        if 'status' in body:
            update_expr += '#status = :status, '
            expr_attrs['#status'] = 'status'
            expr_values[':status'] = body['status']
            
        if 'user_comment' in body:
            update_expr += '#comment = :comment, '
            expr_attrs['#comment'] = 'user_comment'
            expr_values[':comment'] = body['user_comment']
            
        # Add last updated timestamp
        update_expr += '#updated_at = :updated_at'
        expr_attrs['#updated_at'] = 'updated_at'
        expr_values[':updated_at'] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        
        # Update the task
        table.update_item(
            Key={'task_id': task_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attrs,
            ExpressionAttributeValues=expr_values
        )
        
        
        # If status is changed to 'COMPLETED', notify administrators
        if body.get('status') and (body.get('status') == 'COMPLETED' or body.get('status').lower() == 'completed'):
            logger.info("notifying the...")
            try:
                notify_task_completion(current_task, user_email)
            except Exception as e:
                print(f"Error notifying task completion: {str(e)}")
            
        return {
            'statusCode': 200,
            'headers': myHeaders,
            'body': json.dumps({
                'message': 'Task updated successfully',
                'task_id': task_id
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': myHeaders,
            'body': json.dumps({'error': str(e)})
        }


def delete_the_task(event, context):
    # TODO: implement logic so that only admins can do this

    try:
            
        task_id = event['pathParameters']['taskId']
        
        # Delete the task
        response = table.delete_item(
            Key={'task_id': task_id},
            ReturnValues='ALL_OLD'  # This will return the deleted item
        )
        
        # Check if the item existed before deletion
        if 'Attributes' not in response:
            return {
                'statusCode': 404,
                'headers': myHeaders,
                'body': json.dumps({'error': 'Task not found'})
            }
            
        return {
            'statusCode': 200,
            'headers': myHeaders,
            'body': json.dumps({
                'message': 'Task deleted successfully',
                'deletedTask': response['Attributes']
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': myHeaders,
            'body': json.dumps({'error': str(e)})
        }


def get_the_task_by_id(event, context):
    try:
        task_id = event['pathParameters']['taskId']
        
        # Get the specific task from DynamoDB
        response = table.get_item(
            Key={'task_id': task_id}
        )
        
        # Check if the task exists
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': myHeaders,
                'body': json.dumps({'error': 'Task not found'})
            }
            
        return {
            'statusCode': 200,
            'headers': myHeaders,
            'body': json.dumps(response['Item'])
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': myHeaders,
            'body': json.dumps({'error': str(e)})
        }


def get_the_user_tasks(event, context):
    print("Event for get user tasks ...")
    print(event)
    print("proceeding to get user tasks...")

    try:
        # Get user ID from path parameters
        user_email = event['pathParameters']['userId']
        
        # Get tasks for specific user
        response = table.scan(
            FilterExpression='responsibility = :user',
            ExpressionAttributeValues={
                ':user': user_email
            }
        )
        
        tasks = response['Items']
        
        # Handle pagination if there are more items
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey'],
                FilterExpression='responsibility = :user',
                ExpressionAttributeValues={
                    ':user': user_email
                }
            )
            tasks.extend(response['Items'])

        return {
            'statusCode': 200,
            'headers': myHeaders,
            'body': json.dumps({
                'tasks': tasks,
                'count': len(tasks),
                'user': user_email
            })
        }
    except KeyError:
        return {
            'statusCode': 400,
            'headers': myHeaders,
            'body': json.dumps({
                'error': 'Missing user ID in path parameters'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': myHeaders,
            'body': json.dumps({
                'error': str(e)
            })
        }


def create_email_message(task):
    """Create formatted email message for task assignment"""
    return f"""
    New Task Assignment

    You have been assigned a new task:

    Task Details:
    -------------
    Task Name: {task['name']}
    Description: {task['description']}
    Deadline: {task['deadline']}
    Current Status: {task['status']}
    
    Action Required:
    ---------------
    Please log in to the system to:
    1. Review the task details
    2. Acknowledge the assignment
    3. Begin working on the task
    
    Note: This task must be completed by {task['deadline']}
    
    System Link: https://main.d3p2bymp0gir41.amplifyapp.com
    
    This is an automated message. Please do not reply to this email.
    """


def publish_to_sns(task, email_message):
    """Publish task notification to SNS topic"""
    message = {
        'default': json.dumps(task),
        'email': email_message
    }

    try:
        logger.info(f"Publishing to SNS topic: {os.environ['ASSIGNMENT_TOPIC_ARN']}")
        response = sns.publish(
            TopicArn=os.environ['ASSIGNMENT_TOPIC_ARN'],
            Message=json.dumps(message),
            MessageStructure='json',
            MessageAttributes={
                'responsibility': {
                    'DataType': 'String',
                    'StringValue': task['responsibility']
                },
                'taskId': {
                    'DataType': 'String',
                    'StringValue': str(task.get('task_id', 'unknown'))
                },
                'taskStatus': {
                    'DataType': 'String',
                    'StringValue': task['status']
                }
            }
        )
        logger.info(f"Successfully published message: {response['MessageId']}")
        return response
    except Exception as e:
        logger.error(f"Error publishing to SNS: {str(e)}")
        raise


def process_the_task_assignment(event, context):
    """Process tasks from SQS queue and send notifications"""
    logger.info("Starting task assignment processing...")
    logger.info(f"Event: {json.dumps(event)}")
    
    processed_tasks = []
    failed_tasks = []
    
    try:
        for record in event['Records']:
            try:
                # Parse the task from SQS message
                task = json.loads(record['body'])
                logger.info(f"Processing task: {json.dumps(task)}")
                
                # Validate required fields
                required_fields = ['name', 'description', 'deadline', 'status', 'responsibility']
                if not all(field in task for field in required_fields):
                    raise ValueError(f"Missing required fields in task: {task}")
                
                # Create email message
                email_message = create_email_message(task)
                
                # Publish to SNS
                response = publish_to_sns(task, email_message)
                
                processed_tasks.append({
                    'taskId': task.get('task_id', 'unknown'),
                    'messageId': response['MessageId']
                })
                
            except Exception as e:
                logger.error(f"Error processing individual task: {str(e)}")
                failed_tasks.append({
                    'taskId': task.get('task_id', 'unknown'),
                    'error': str(e)
                })
                continue  # Continue processing other tasks
        
        # Prepare response
        response_body = {
            'message': 'Task assignment processing completed',
            'timestamp': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            'processed': processed_tasks,
            'failed': failed_tasks
        }
        
        status_code = 200 if not failed_tasks else 207  # Use 207 if some tasks failed
        
        return {
            'statusCode': status_code,
            'body': json.dumps(response_body)
        }
        
    except Exception as e:
        logger.error(f"Critical error in task processing: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            })
        }


def publish_to_sns_task_deadline(task, email_message):

    message = {
        'default': json.dumps(task),
        'email': email_message
    }

    try:
        response = sns.publish(
            TopicArn=os.environ['DEADLINE_TOPIC_ARN'],
            Message=json.dumps(message),
            MessageStructure='json',
            MessageAttributes={
                'responsibility': {
                    'DataType': 'String',
                    'StringValue': task['responsibility']
                },
                'taskId': {
                    'DataType': 'String',
                    'StringValue': str(task.get('task_id', 'unknown'))
                },
                'taskStatus': {
                    'DataType': 'String',
                    'StringValue': task['status']
                }
            }
        )

        return response;
    
    except Exception as e:
        print(f"Error publishing to SNS: {str(e)}")
        raise
    

    


def process_the_deadline_notification(event, context):

    print("processing deadline notification...")

    processed_tasks = []
    failed_tasks = []

    try:
    
        for record in event['Records']:
            try:
                task = json.loads(record['body'])

                email_message = create_deadline_warning_email(task)
                
                response = publish_to_sns_task_deadline(task, email_message)
                
                processed_tasks.append({
                    'taskId': task.get('task_id', 'unknown'),
                    'messageId': response['MessageId']
                })
            except Exception as e:
                failed_tasks.append({
                    'taskId': task.get('task_id', 'unknown'),
                    'error': str(e)
                })
                continue
        
        # Prepare response
        response_body = {
            'message': 'Task deadline processing completed',
            'timestamp': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            'processed': processed_tasks,
            'failed': failed_tasks
        }

        status_code = 200 if not failed_tasks else 207  # Use 207 if some tasks failed

        return {
            'statusCode': status_code,
            'body': json.dumps(response_body)
        }

    except Exception as e:
        logger.error(f"Critical error in task processing: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            })
        }
        

def handle_dead_letter_queue(event, context):
    """Handle failed messages from DLQ"""
    logger.info("Processing messages from DLQ...")
    
    try:
        for record in event['Records']:
            # Log failed message for investigation
            logger.error(f"Failed message: {record['body']}")
            
            # You could implement retry logic here
            # Or send to a different notification channel
            
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Processed DLQ messages',
                'timestamp': datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            })
        }
    except Exception as e:
        logger.error(f"Error processing DLQ: {str(e)}")
        raise


def send_status_update_notification(task, new_status, updated_by):
    try:
        message = {
            'default': json.dumps({
                'task_id': task['task_id'],
                'title': task['name'],
                'new_status': new_status,
                'updated_by': updated_by
            }),
            'email': f"""
                Task Status Update
                
                Task: {task['name']}
                New Status: {new_status}
                Updated By: {updated_by}
                
                Task Details:
                Description: {task['description']}
                Deadline: {task['deadline']}
            """
        }
        
        sns.publish(
            TopicArn=os.environ['ASSIGNMENT_TOPIC_ARN'],
            Message=json.dumps(message),
            MessageStructure='json',
            MessageAttributes={
                'responsibility': {
                    'DataType': 'String',
                    'StringValue': task['responsibility']
                }
            }
        )
    except Exception as e:
        print(f"Error sending status update notification: {str(e)}")


def reopen_the_task(event, context):
    print("repoening a task...")
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Get task ID from path parameters
        task_id = event['pathParameters']['taskId']
        logger.info(f"Processing task_id: {task_id}")
        
        # Get user information from Cognito authorizer
        user_email = event['requestContext']['authorizer']['claims']['email']
        user_groups = event['requestContext']['authorizer']['claims'].get('cognito:groups', [])
        logger.info(f"User email: {user_email}, Groups: {user_groups}")
        
        # Check if user is administrator
        if 'Admin' not in user_groups:
            return {
                'statusCode': 403,
                'headers': myHeaders,
                'body': json.dumps({
                    'error': 'Only administrators can reopen tasks'
                })
            }
        
        # Get the current task
        task_response = table.get_item(
            Key={'task_id': task_id}
        )
        
        if 'Item' not in task_response:
            return {
                'statusCode': 404,
                'headers': myHeaders,
                'body': json.dumps({'error': 'Task not found'})
            }
            
        current_task = task_response['Item']
        logger.info(f"Current task status: {current_task['status']}")
        
        # Check if task is closed or expired
        if current_task['status'] not in ['completed', 'expired']:
            return {
                'statusCode': 400,
                'headers': myHeaders,
                'body': json.dumps({
                    'error': 'Only completed or expired tasks can be reopened'
                })
            }

        # Calculate new deadline (current time + 2 minutes)
        new_deadline = (datetime.now(timezone.utc) + timedelta(minutes=60)).replace(tzinfo=None).isoformat()
        logger.info(f"New deadline calculated: {new_deadline}")
        
        # Update task status and extend deadline
        update_response = table.update_item(
            Key={'task_id': task_id},
            UpdateExpression='SET #status = :status, #reopened_at = :reopened_at, #reopened_by = :reopened_by, #deadline = :new_deadline',
            ExpressionAttributeNames={
                '#status': 'status',
                '#reopened_at': 'reopened_at',
                '#reopened_by': 'reopened_by',
                '#deadline': 'deadline'
            },
            ExpressionAttributeValues={
                ':status': 'open',
                ':reopened_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                ':reopened_by': user_email,
                ':new_deadline': new_deadline
            },
            ReturnValues='ALL_NEW'
        )

        updated_task = update_response['Attributes']
        logger.info(f"Task updated successfully: {json.dumps(updated_task)}")

        # Prepare notification message
        message = {
            'default': json.dumps({
                'task_id': updated_task['task_id'],
                'name': updated_task['name'],
                'status': 'reopened',
                'reopened_by': updated_task['reopened_by'],
                'reopened_at': updated_task['reopened_at'],
                'responsibility': updated_task['responsibility'],
                'deadline': updated_task['deadline']
            }),
            'email': (
                f"Task Reopened\n\n"
                f"Task Name: {updated_task['name']}\n"
                f"Task ID: {updated_task['task_id']}\n"
                f"Reopened By: {updated_task['reopened_by']}\n"
                f"Reopened At: {updated_task['reopened_at']}\n"
                f"Extended Deadline: {updated_task['deadline']}\n\n"
                f"The task has been reopened and the deadline has been extended.\n"
                f"Please complete the task before the new deadline."
            )
        }

        logger.info("Publishing to SNS...")
        # Publish to SNS with message attributes for filtering
        sns.publish(
            TopicArn=os.environ['REOPENED_TOPIC_ARN'],
            Message=json.dumps(message),
            MessageStructure='json',
            MessageAttributes={
                'responsibility': {
                    'DataType': 'String',
                    'StringValue': updated_task['responsibility']
                }
            }
        )
        logger.info("Successfully published to SNS")

        return {
            'statusCode': 200,
            'headers': myHeaders,
            'body': json.dumps(updated_task)
        }

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': myHeaders,
            'body': json.dumps({
                'error': f"Unexpected error: {str(e)}"
            })
        }
    # except ClientError as e:
    #     logger.error(f"AWS Error: {str(e)}")
    #     return {
    #         'statusCode': 500,
    #         'headers': myHeaders,
    #         'body': json.dumps({
    #             'error': str(e)
    #         })
    #     }



##################################################
##################################################
##################################################

# Deadline checker section


##################################################
##################################################
##################################################

def create_deadline_warning_email(task):
    return f"""
    ⚠️ URGENT: Task Deadline Approaching
    
    The following task is due in less than 1 minute:
    
    Task Name: {task['name']}
    Description: {task['description']}
    Deadline: {task['deadline']}
    Current Status: {task['status']}
    
    Please take immediate action on this task.
    
    Task Details:
    ID: {task['task_id']}
    Assigned To: {task['responsibility']}
    """


def send_to_SQS(task):
    try:
        
        # response = sns.publish(
        #     TopicArn=os.environ['DEADLINE_TOPIC_ARN'],
        #     Message=json.dumps(message),
        #     MessageStructure='json',
        #     MessageAttributes={
        #         'responsibility': {
        #             'DataType': 'String',
        #             'StringValue': task['responsibility']
        #         }
        #     }
        # )
        # logger.info(f"Sent deadline warning for task {task['task_id']}, SNS MessageId: {response['MessageId']}")

        sqs.send_message(
            QueueUrl=os.environ['DEADLINE_QUEUE_URL'],
            MessageBody=json.dumps(task)
        )

    except Exception as e:
        logger.error(f"Error sending deadline warning for task {task['task_id']}: {str(e)}", exc_info=True)
        raise


def queue_expired_task(task):
    try:
        response = sqs.send_message(
            QueueUrl=os.environ['EXPIRED_TASKS_QUEUE'],
            MessageBody=json.dumps(task),
            MessageAttributes={
                'task_id': {
                    'DataType': 'String',
                    'StringValue': task['task_id']
                }
            }
        )
        logger.info(f"Queued expired task {task['task_id']}, SQS MessageId: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error queuing expired task {task['task_id']}: {str(e)}", exc_info=True)
        raise


def check_the_deadline(event, context):
    logger.info("Deadline checker started")
    logger.info(f"Event: {json.dumps(event)}")

    # now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    now = datetime.now(timezone.utc)
    one_minute_from_now = now + timedelta(minutes=60) # will change this time
    
    logger.info(f"Checking for tasks between {now.replace(tzinfo=None).isoformat()} and {one_minute_from_now.replace(tzinfo=None).isoformat()}")
    
    try:
        # Check for tasks approaching deadline (1 minute warning)
        approaching_deadline = table.scan(
            FilterExpression=Attr('deadline').between(
                now.replace(tzinfo=None).isoformat(),
                one_minute_from_now.replace(tzinfo=None).isoformat()
            ) & Attr('status').ne('expired') & Attr('status').ne('completed')

        )
        
        tasks_approaching = approaching_deadline.get('Items', [])
        logger.info(f"Found {len(tasks_approaching)} tasks approaching deadline")
        
        # Send warnings for approaching deadlines
        for task in tasks_approaching:
            logger.info(f"Processing warning for task: {task['task_id']}")
            send_to_SQS(task) # send to SQS
        
        #  commenting out expired task for now

        # Check for expired tasks
        expired_tasks_response = table.scan(
            FilterExpression=Attr('deadline').lt(now.replace(tzinfo=None).isoformat()) & 
                            Attr('status').ne('expired') & Attr('status').ne('completed')
        )
        
        expired_tasks = expired_tasks_response.get('Items', [])
        logger.info(f"Found {len(expired_tasks)} expired tasks")
        
        # # Queue expired tasks
        for task in expired_tasks:
            logger.info(f"Processing expired task: {task['task_id']}")
            queue_expired_task(task)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Deadline check completed',
                'approaching_deadline': len(tasks_approaching)
                # 'expired_tasks': len(expired_tasks)
            })
        }
    except Exception as e:
        logger.error(f"Error in deadline checker: {str(e)}", exc_info=True)
        raise


def expired_tasks_processor(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        for record in event['Records']:
            # Parse the SQS message body
            task = json.loads(record['body'])
            logger.info(f"Processing task: {json.dumps(task)}")
            
            # Start step function execution
            response = stepfunctions.start_execution(
                stateMachineArn=os.environ['STATE_MACHINE_ARN'],
                input=json.dumps(task)
            )
            
            logger.info(f"Started Step Function execution: {response['executionArn']}")
            
        return {
            'statusCode': 200,
            'body': json.dumps('Successfully processed expired tasks')
        }
        
    except Exception as e:
        logger.error(f"Error processing expired tasks: {str(e)}", exc_info=True)
        raise
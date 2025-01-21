{
    "Comment": "Workflow for handling expired tasks",
    "StartAt": "UpdateTaskStatus",
    "States": {
        "UpdateTaskStatus": {
            "Type": "Task",
            "Resource": "arn:aws:states:::dynamodb:updateItem",
            "Parameters": {
                "TableName": "${TasksTable}",
                "Key": {
                    "task_id": {
                        "S.$": "$.task_id"
                    }
                },
                "UpdateExpression": "SET #status = :status, #expired_at = :expired_at",
                "ExpressionAttributeNames": {
                    "#status": "status",
                    "#expired_at": "expired_at"
                },
                "ExpressionAttributeValues": {
                    ":status": {
                        "S": "expired"
                    },
                    ":expired_at": {
                        "S.$": "$$.State.EnteredTime"
                    }
                },
                "ReturnValues": "ALL_NEW"
            },
            "ResultPath": "$.dynamodbResult",
            "Next": "PrepareNotification"
        },
        "PrepareNotification": {
            "Type": "Pass",
            "Parameters": {
                "task_id.$": "$.dynamodbResult.Attributes.task_id.S",
                "name.$": "$.dynamodbResult.Attributes.name.S",
                "responsibility.$": "$.dynamodbResult.Attributes.responsibility.S",
                "status": "expired",
                "expired_at.$": "$.dynamodbResult.Attributes.expired_at.S",
                "messageData": {
                    "task_id.$": "$.dynamodbResult.Attributes.task_id.S",
                    "name.$": "$.dynamodbResult.Attributes.name.S",
                    "status": "expired",
                    "message": "Task has expired",
                    "expired_at.$": "$.dynamodbResult.Attributes.expired_at.S",
                    "responsibility.$": "$.dynamodbResult.Attributes.responsibility.S"
                }
            },
            "Next": "CreateEmailMessage"
        },
        "CreateEmailMessage": {
            "Type": "Pass",
            "Parameters": {
                "emailBody": {
                    "Fn::Join": [
                        "",
                        [
                            "Task Expired\n\nTask Name: ",
                            {
                                "$": "$.name"
                            },
                            "\nTask ID: ",
                            {
                                "$": "$.task_id"
                            },
                            "\nAssigned To: ",
                            {
                                "$": "$.responsibility"
                            },
                            "\nExpired At: ",
                            {
                                "$": "$.expired_at"
                            },
                            "\n\nThe task has been marked as expired due to passing its deadline."
                        ]
                    ]
                },
                "defaultMessage.$": "States.JsonToString($.messageData)",
                "responsibility.$": "$.responsibility"
            },
            "Next": "NotifyUsers"
        },
        "NotifyUsers": {
            "Type": "Task",
            "Resource": "arn:aws:states:::sns:publish",
            "Parameters": {
                "TopicArn": "${ClosedTasksNotificationTopic}",
                "Message": {
                    "default.$": "$.defaultMessage",
                    "email.$": "$.emailBody"
                },
                "MessageStructure": "json",
                "MessageAttributes": {
                    "responsibility": {
                        "DataType": "String",
                        "StringValue.$": "$.responsibility"
                    }
                }
            },
            "End": true
        }
    }
  }

===

  UserSubscriptionWorkflow:
    Type: AWS::Serverless::StateMachine
    Properties:
      Type: EXPRESS
      Role: !GetAtt UserSubscriptionWorkflowRole.Arn
      Logging:
        Level: ALL
        IncludeExecutionData: true
        Destinations:
          - CloudWatchLogsLogGroup:
              LogGroupArn: !GetAtt UserSubscriptionWorkflowLogGroup.Arn
      Definition:
        StartAt: SubscribeToTopics
        States:
          SubscribeToTopics:
            Type: Parallel
            Branches:
              - StartAt: SubscribeToAssignment
                States:
                  SubscribeToAssignment:
                    Type: Task
                    Resource: !GetAtt SubscribeUserToTopicFunction.Arn
                    Parameters:
                      "TopicArn": !Ref TasksAssignmentNotificationTopic
                      "Protocol": "email"
                      "Endpoint.$": "$.email"
                    End: true
              - StartAt: SubscribeToDeadline
                States:
                  SubscribeToDeadline:
                    Type: Task
                    Resource: !GetAtt SubscribeUserToTopicFunction.Arn
                    Parameters:
                      "TopicArn": !Ref TasksDeadlineNotificationTopic
                      "Protocol": "email"
                      "Endpoint.$": "$.email"
                    End: true
              - StartAt: SubscribeToClosed
                States:
                  SubscribeToClosed:
                    Type: Task
                    Resource: !GetAtt SubscribeUserToTopicFunction.Arn
                    Parameters:
                      "TopicArn": !Ref ClosedTasksNotificationTopic
                      "Protocol": "email"
                      "Endpoint.$": "$.email"
                    End: true
              - StartAt: SubscribeToReopened
                States:
                  SubscribeToReopened:
                    Type: Task
                    Resource: !GetAtt SubscribeUserToTopicFunction.Arn
                    Parameters:
                      "TopicArn": !Ref ReopenedTasksNotificationTopic
                      "Protocol": "email"
                      "Endpoint.$": "$.email"
                    End: true
              - StartAt: SubscribeToCompletion
                States:
                  SubscribeToCompletion:
                    Type: Task
                    Resource: !GetAtt SubscribeUserToTopicFunction.Arn
                    Parameters:
                      "TopicArn": !Ref TasksCompletionNotificationTopic
                      "Protocol": "email"
                      "Endpoint.$": "$.email"
                    End: true
            End: true

===

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
        
        logger.info(f"Subscribing {endpoint} to topic {topic_arn}")
        
        # Create the subscription
        response = sns.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint,
            ReturnSubscriptionArn=True
        )
        
        subscription_arn = response['SubscriptionArn']
        
        # If this is the assignment notification topic, set up filtering
        if topic_arn.endswith('TasksAssignmentNotificationTopic'):
            logger.info("Setting up filter policy for assignment notifications")
            sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName='FilterPolicy',
                AttributeValue=json.dumps({
                    'responsibility': [endpoint]  # Filter by assigned user's email
                })
            )

        # If this is the deadline notification topic, set up filtering
        if topic_arn.endswith('TasksDeadlineNotificationTopic'):
            logger.info("Setting up filter policy for deadline notifications")
            sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName='FilterPolicy',
                AttributeValue=json.dumps({
                    'responsibility': [endpoint]  # Filter by assigned user's email
                })
            )

        if topic_arn.endswith('ClosedTasksNotificationTopic'):
            logger.info("Setting up filter policy for closed notifications")
            sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName='FilterPolicy',
                AttributeValue=json.dumps({
                    'responsibility': [endpoint]  # Filter by assigned user's email
                })
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

===
        try:

            # Get current user attributes
            user_response = cognito.admin_get_user(
                UserPoolId=user_pool_id,
                Username=username
            )

            # Convert user attributes to dictionary for easier access
            current_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}

            # Convert current attributes back to Cognito format, maintaining all existing attributes
            required_attributes = [
                {'Name': key, 'Value': value} 
                for key, value in current_attributes.items()
            ]

            # Update or add custom:role if needed
            role_exists = False
            for attr in required_attributes:
                if attr['Name'] == 'custom:role':
                    attr['Value'] = 'TeamMember'
                    role_exists = True
                    break
            
            if not role_exists:
                required_attributes.append({
                    'Name': 'custom:role',
                    'Value': 'TeamMember'
                })
            
            print(f"Updating user attributes for {username}")
            cognito.admin_update_user_attributes(
                UserPoolId=user_pool_id,
                Username=username,
                UserAttributes=required_attributes
            )
        
        except Exception as e:
            print(f"Error in make_sure_role_exists: {str(e)}")

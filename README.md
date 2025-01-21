# Task Management System (TMS)

A serverless task management solution built with AWS SAM, featuring real-time notifications, role-based access control, and automated task tracking.

## Project Overview

TMS is a cloud-native application that helps teams manage tasks efficiently with features like task assignment, deadline tracking, and automated notifications. Built using AWS Serverless Application Model (SAM), it provides a scalable and maintainable solution for task management.

### Key Features

- 🔐 Secure authentication and authorization
- 📋 Task creation, assignment, and tracking
- 📢 Real-time notifications for task updates
- ⏰ Automated deadline reminders
- 👥 Role-based access control (Admin/Team Member)
- 📊 Task status monitoring
- 🔄 Automated workflow management

## Architecture

The system is built using the following AWS services:

- **Authentication**: Amazon Cognito
- **Database**: Amazon DynamoDB
- **Computing**: AWS Lambda
- **API Layer**: Amazon API Gateway
- **Notifications**: Amazon SNS, Amazon SQS
- **Workflow**: AWS Step Functions

## Prerequisites

- AWS Account
- AWS SAM CLI installed
- Node.js 14.x or later
- Python 3.12 or later
- AWS CLI configured with appropriate credentials

## Project Structure

- Important Files are listed here

```plaintext
tms_back_end
├── user_management/
│   ├── app.py
│   ├── reqirements.txt
├── hello_world/
│   ├── app.py
│   ├── reqirements.txt
├── statemachines/
│   ├── expired_tasks.asl.json
├── tests/
│   ├── unit/
│   ├── integration/
├── template.yaml
└── README.md
```

## Security
- All API endpoints are secured with Cognito authentication
- Data is encrypted at rest in DynamoDB
- Secure communication using HTTPS
- Role-based access control implemented
- Environment variables for sensitive data

### Related Repositories
- 🎯 TMS Frontend: [https://github.com/frankkwabenaaboagye/amplify-angular-template](https://github.com/frankkwabenaaboagye/amplify-angular-template)


## Architecture Diagram
```mermaid

graph TB
    subgraph "Authentication" 
        Cognito["🔐 Amazon Cognito<br/>User Pool"]
        IdentityPool["🔑 Cognito<br/>Identity Pool"]
    end

    subgraph "Frontend"
        WebApp["💻 Angular<br/>Web Application"]
    end

    subgraph "Storage"
        DDB["📦 Amazon DynamoDB<br/>Tasks Table"]
    end

    subgraph "Notification System"
        SNS1["📢 SNS Topic:<br/>Task Assignment"]
        SNS2["📢 SNS Topic:<br/>Task Deadline"]
        SNS3["📢 SNS Topic:<br/>Task Completion"]
        SNS4["📢 SNS Topic:<br/>Closed Tasks"]
        SNS5["📢 SNS Topic:<br/>Reopened Tasks"]
    end

    subgraph "Message Processing"
        SQS1["📫 SQS:<br/>Task Assignment Queue"]
        SQS2["📫 SQS:<br/>Deadline Queue"]
    end

    subgraph "Step Functions"
        SF["⚙️ User Subscription<br/>Workflow"]
    end

    subgraph "Lambda Functions"
        L1["λ Subscribe User<br/>To Topic"]
        L2["λ Process Deadline<br/>Notification"]
        L3["λ Get Tasks"]
        L4["λ Update Task"]
        L5["λ Get Task By ID"]
        L6["λ Delete Task"]
    end

    %% Connections
    WebApp -->|"Authenticates"| Cognito
    Cognito -->|"Provides Tokens"| IdentityPool
    IdentityPool -->|"Assumes Roles"| WebApp

    WebApp -->|"CRUD Operations"| DDB
    L3 & L4 & L5 & L6 -->|"Access"| DDB

    SF -->|"Manages Subscriptions"| L1
    L1 -->|"Subscribe Users"| SNS1
    L1 -->|"Subscribe Users"| SNS2
    L1 -->|"Subscribe Users"| SNS3
    L1 -->|"Subscribe Users"| SNS4
    L1 -->|"Subscribe Users"| SNS5

    SNS1 -->|"Notifications"| SQS1
    SNS2 -->|"Notifications"| SQS2

    SQS1 -->|"Triggers"| L2
    SQS2 -->|"Triggers"| L2

    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:white;
    class Cognito,IdentityPool,DDB,SNS1,SNS2,SNS3,SNS4,SNS5,SQS1,SQS2,SF,L1,L2,L3,L4,L5,L6 aws;

```


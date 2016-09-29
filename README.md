# AWS Network Helper
Project for submission to the 2016 AWS Serverless Chatbot Competition

## Goals & Features
The goal of this project is to provide an AWS network troubleshooting script that runs on a serverless architecture, and can be interacted with via Slack as a chat bot. In simple terms, the goal is to be able to respond to input like:

* Why can’t I connect to ec2-instance-A from ec2-instance-B?
* Troubleshoot connection between ec2-instance-B and rds-instance-C on port 5432
* I cannot connect to S3 from ec2-instance-A
* Help me connect to ec2-instance-B

In order to respond to inputs like these, the script must be able to analyze these network elements:

* Ingress and Egress Security Groups
* Ingress and Egress Network ACLs
* Route Tables
* NAT and Internet Gateways

Also, since information like instance type, port, and ephemeral ports may or may not be provided, the code must be able to look through metadata for these values, or at least make reasonable assumptions for what the user is most likely trying to accomplish.

The code is currently able to understand all of the statements above, as well as small variations in the wording. It can troubleshoot network settings for the following types of connections in both directions:

| Instance A | Instance B   | Complexities                                             |
|------------|--------------|----------------------------------------------------------|
| EC2        | EC2          | Supports Windows and Linux                               |
| EC2        | RDS          | All RDS engine types supported                           |
| EC2        | The Internet | Supports instances behind both Internet and NAT Gateways |
| RDS        | The Internet | Supports instances behind both Internet and NAT Gateways |
| EC2        | AWS Services | S3, DynamoDB, KMS, SNS, SQS, etc.                        |

Wherever possible, the code should also not limit the scope of this project to only use Slack as the messaging interface.


## Architecture

AWS Services Used:
* API Gateway
* SNS
* S3
* Lambda
* IAM & KMS

![Architecture Diagram](aws-network-helper/docs/AWS Network Helper Architecture.png?raw=true "AWS Network Helper Architecture Diagram")

An SNS topic is used between the Slack listener Lambda and the network helper Lambda so that in the future, different listeners could be deployed that use interfaces other than Slack. Other interfaces could include, but are not limited to:

* A web app
* A scheduled batch job for auditing network settings
* A command line tool
* A Python module

S3 is used to provide the user with an externalized configuration file for easier changes. The Slack token, SNS ARN, slash command, and other variables can be changed without re-compiling your Lambda

KMS is used to decrypt the Slack token stored in the configuration file upon use, and is also used to encrypt/decrypt the response URL as it gets passed through SNS. This is an added layer of security.

# SSL Certificate Checker

## Overview

This Python script automates the process of checking SSL certificates for specific services across a network of servers, ensuring their validity and timely issuance. It alerts the engineering team via Slack about any certificates that are expiring, expired, or if there are any connection issues. Additionally, it records the status of the certificates on a statsd server for observability.

## Features

- **Automated SSL Certificate Checks**: Validates certificates for specified services to ensure they are valid and recently issued.
- **Notification System**: Sends alerts through Slack for certificates that are expiring, expired, or when connection issues are detected.
- **Metrics Tracking**: Updates metrics on a statsd server to monitor the status of the certificates for each service.
- **Concurrency**: Utilizes threading to perform checks across multiple servers concurrently for efficient operation.
- **Input Validation and Sanitization**: Prevents injection attacks by validating and sanitizing inputs.
- **Verbose Logging**: Supports a verbose mode that provides detailed logging, aiding in debugging and monitoring.

## Setup

1. **Install Dependencies**: Ensure you have Python `3.x` installed, and then install the required Python packages by running:
   ```
   pip install requests statsd
   ```

2. **Configuration**:
- Update the `SLACK_WEBHOOK_URL` in the script with your actual Slack webhook URL.
- Ensure the `IP_ADDRESSES_FILE` path points to your file containing the IP addresses and service names.

3. **Running the Script**:
- To run the script in normal mode:
  ```
  python run.py
  ```
- To enable verbose (debug) logging:
  ```
  python run.py -v
  ```

## Contributing

Contributions to improve the script or address issues are welcome. Please feel free to submit pull requests or create issues in the repository.

## Follow Up Questions

### Ensuring the Script Runs Correctly

To ensure the script is running correctly, implement unit tests using Python's `unittest` framework. For example, test the `is_valid_ip` and `is_valid_port` functions with valid and invalid inputs. Additionally, integrate logging throughout the script to capture runtime operations and potential issues. Example for a simple test:

```python
import unittest
from your_script import is_valid_ip

class TestIPAddressValidation(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(is_valid_ip('192.168.1.1'))

    def test_invalid_ip(self):
        self.assertFalse(is_valid_ip('256.256.256.256'))

if __name__ == '__main__':
    unittest.main()
```

### Dockerizing a Test Environment

To dockerize a test environment, create a Dockerfile that sets up Python, installs dependencies, and runs your script. Example Dockerfile:

```Dockerfile
FROM python:3.8
WORKDIR /app
COPY . /app
RUN pip install requests statsd
CMD ["python", "run.py"]
```

Build and run the Docker container with:

```
docker build -t ssl-checker .
docker run ssl-checker
```

### Deploying on an AWS EC2 Instance Using Terraform

To deploy on AWS EC2 with Terraform, define your infrastructure as code in a Terraform configuration file (e.g., main.tf). Example main.tf:

```
provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "app" {
  ami           = "ami-###"
  instance_type = "t2.micro"
  key_name      = "your-ssh-key"

  provisioner "file" {
    source      = "path/to/your/script"
    destination = "/home/ubuntu/run.py"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y python3-pip",
      "pip3 install requests statsd",
      "python3 /home/ubuntu/run.py"
    ]
  }

  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file("${path.module}/your-ssh-key.pem")
    host        = self.public_ip
  }
}
```

Initialize Terraform, plan, and apply to deploy:

```
terraform init
terraform plan
terraform apply
```

### Configuring the Script to Run Every X Days

To run the script every X days within a virtual network, use `cron` on Linux. Edit the crontab with `crontab -e` and add a line specifying the schedule and script path. For example, to run it every 5 days:

```
0 0 */5 * * /usr/bin/python3 /path/to/run.py
```

This crontab entry will execute the script at midnight every 5 days. Ensure the Python path (`/usr/bin/python3`) and script path (`/path/to/run.py`) are correctly specified for your environment.

provider "aws" {
  region = "us-east-2"
}


resource "aws_vpc" "ecs_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "ecs-capstone-vpc" }
}
resource "aws_subnet" "public_subnet_1" {
  vpc_id            = aws_vpc.ecs_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-2a"
  tags = { Name = "ecs-subnet-1" }
}
resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.ecs_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-2b"
  tags = { Name = "ecs-subnet-2" }
}
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.ecs_vpc.id
  tags   = { Name = "ecs-igw" }
}
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.ecs_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = { Name = "ecs-public-rt" }
}
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}
resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}


resource "aws_ecs_cluster" "ecs_cluster" {
  name = "ecs-capstone-cluster"
}


resource "aws_iam_role" "ecs_instance_role" {
  name = "ecsInstanceRole"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "ecs_instance_role_attachment" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}
resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecsInstanceProfile"
  role = aws_iam_role.ecs_instance_role.name
}

resource "aws_iam_role_policy" "ecs_instance_role_policy" {
  name = "ecs_instance_role_policy"
  role = aws_iam_role.ecs_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:ListTasks"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_security_group" "ecs_sg" {
  name        = "ecs-sg"
  description = "ECS instances"
  vpc_id      = aws_vpc.ecs_vpc.id
  # SSH for admin (tighten in prod)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # ALB -> container port (80)
  ingress {
    description     = "ALB to ECS :80"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  # ALB -> dynamic host ports for bridge mode (32768–65535)
  ingress {
    description     = "ALB to ECS ephemeral ports"
    from_port       = 32768
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "ecs-security-group" }
}

resource "aws_security_group" "alb_sg" {
  name        = "pacman-alb-sg"
  description = "ALB ingress 80 from internet; egress to ECS"
  vpc_id      = aws_vpc.ecs_vpc.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "pacman-alb-sg" }
}

resource "aws_launch_template" "ecs_launch_template" {
  name_prefix   = "ecs-capstone-"
  image_id      = "ami-0bb72f6ed1add75ee" # ECS-optimized AMI (us-east-2)
  instance_type = "t3.small"
  key_name      = "ecs-key"
  user_data = base64encode(<<EOF
#!/bin/bash
set -xe
mkdir -p /etc/ecs /var/log/ecs /var/lib/ecs/data
echo "ECS_CLUSTER=ecs-capstone-cluster" > /etc/ecs/ecs.config
echo "ECS_ENABLE_CONTAINER_METADATA=true" >> /etc/ecs/ecs.config
echo "ECS_AVAILABLE_LOGGING_DRIVERS=[\"json-file\",\"awslogs\"]" >> /etc/ecs/ecs.config
yum clean all -y
yum install -y docker ecs-init
systemctl enable --now docker
systemctl enable ecs
systemctl start ecs
EOF
)

  iam_instance_profile {
    name = aws_iam_instance_profile.ecs_instance_profile.name
  }
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ecs_sg.id]
  }
  tag_specifications {
    resource_type = "instance"
    tags = { Name = "ecs-capstone-ec2" }
  }
}
resource "aws_autoscaling_group" "ecs_asg" {
  name                = "ecs-capstone-asg"
  max_size            = 4
  min_size            = 2
  desired_capacity    = 2
  vpc_zone_identifier = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  launch_template {
    id      = aws_launch_template.ecs_launch_template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ecs-capstone-ec2"
    propagate_at_launch = true
  }
}


resource "aws_appautoscaling_target" "ecs_tasks" {
  max_capacity       = 6
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.ecs_cluster.name}/${aws_ecs_service.pacman_service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ecs_tt_cpu" {
  name               = "ecs-pacman-tt-cpu-50"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_tasks.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_tasks.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_tasks.service_namespace
  target_tracking_scaling_policy_configuration {
    target_value       = 50.0
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 30
    scale_out_cooldown = 30
  }
}

resource "aws_ecs_task_definition" "pacman_task" {
  family                   = "pacman-server"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  cpu                      = "200"
  memory                   = "700"
  container_definitions = jsonencode([
    {
      name      = "pacman",
      image     = "golucky5/pacman",
      essential = true,
      portMappings = [
        {
          containerPort = 80,
          hostPort      = 0
          protocol      = "tcp"
        }
      ]
    }
  ])
}


resource "aws_lb" "pacman_alb" {
  name               = "pacman-alb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  security_groups    = [aws_security_group.alb_sg.id]
}
resource "aws_lb_target_group" "pacman_tg" {
  name     = "pacman-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.ecs_vpc.id
  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.pacman_alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.pacman_tg.arn
  }
}
resource "aws_ecs_service" "pacman_service" {
  name            = "pacman-service"
  cluster         = aws_ecs_cluster.ecs_cluster.id
  task_definition = aws_ecs_task_definition.pacman_task.arn
  desired_count   = 2
  launch_type     = "EC2"
  load_balancer {
    target_group_arn = aws_lb_target_group.pacman_tg.arn
    container_name   = "pacman"
    container_port   = 80
  }
  depends_on = [aws_lb_listener.http]
}


resource "aws_wafv2_web_acl" "pacman_waf" {
  name        = "Pacman-WAF"
  description = "WAF protecting Pacman ALB"
  scope       = "REGIONAL"
  default_action {
    allow {}
  }
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }
  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }
  rule {
    name     = "AWS-AWSManagedRulesAmazonIpReputationList"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AmazonIpReputation"
      sampled_requests_enabled   = true
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "PacmanWAF"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "pacman_waf_assoc" {
  resource_arn = aws_lb.pacman_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.pacman_waf.arn
}


resource "aws_autoscaling_policy" "tt_cpu_5" {
  name                   = "Packman-TargetTracking-CPU5"
  autoscaling_group_name = aws_autoscaling_group.ecs_asg.name
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value     = 5
    disable_scale_in = false  # allow scale-in
  }
  
  estimated_instance_warmup = 0
}


resource "aws_autoscaling_policy" "step_add2_cpu_gt3" {
  name                   = "Pacman-StepScaling-Add2-CPUgt3"
  autoscaling_group_name = aws_autoscaling_group.ecs_asg.name
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = 2
  cooldown               = 0
}
resource "aws_cloudwatch_metric_alarm" "cpu_gt3_add2" {
  alarm_name          = "CPU-gt-3pct-Add2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 3
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.ecs_asg.name
  }
  alarm_actions = [aws_autoscaling_policy.step_add2_cpu_gt3.arn]
}

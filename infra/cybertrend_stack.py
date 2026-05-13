from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_apigateway as apigw,
)
from aws_cdk import (
    aws_cloudwatch as cloudwatch,
)
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_events as events,
)
from aws_cdk import (
    aws_events_targets as event_targets,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_lambda_event_sources as event_sources,
)
from aws_cdk import (
    aws_rds as rds,
)
from aws_cdk import (
    aws_scheduler as scheduler,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from aws_cdk import (
    aws_ses as ses,
)
from aws_cdk import (
    aws_sns as sns,
)
from aws_cdk import (
    aws_sqs as sqs,
)
from constructs import Construct


class CybertrendStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        root = Path(__file__).resolve().parents[1]
        vpc = ec2.Vpc(
            self,
            "Vpc",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="public", subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(
                    name="private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            ],
        )

        app_secret = secretsmanager.Secret(
            self,
            "AppSecret",
            description="Cybertrend application credentials and API keys.",
            secret_object_value={
                "API_KEY": cdk.SecretValue.unsafe_plain_text("replace-after-deploy"),
                "REDDIT_CLIENT_ID": cdk.SecretValue.unsafe_plain_text(""),
                "REDDIT_CLIENT_SECRET": cdk.SecretValue.unsafe_plain_text(""),
                "NVD_API_KEY": cdk.SecretValue.unsafe_plain_text(""),
                "TENABLE_ACCESS_KEY": cdk.SecretValue.unsafe_plain_text(""),
                "TENABLE_SECRET_KEY": cdk.SecretValue.unsafe_plain_text(""),
                "LLM_API_KEY": cdk.SecretValue.unsafe_plain_text(""),
            },
        )

        database = rds.DatabaseInstance(
            self,
            "Postgres",
            engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_16_3),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MICRO),
            vpc=vpc,
            allocated_storage=20,
            max_allocated_storage=100,
            credentials=rds.Credentials.from_generated_secret("cybertrend"),
            database_name="cybertrend",
            backup_retention=Duration.days(7),
            deletion_protection=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        ingestion_dlq = sqs.Queue(self, "IngestionDlq", retention_period=Duration.days(14))
        ingestion_queue = sqs.Queue(
            self,
            "IngestionQueue",
            visibility_timeout=Duration.minutes(5),
            dead_letter_queue=sqs.DeadLetterQueue(max_receive_count=3, queue=ingestion_dlq),
        )
        alert_dlq = sqs.Queue(self, "AlertDlq", retention_period=Duration.days(14))
        alert_queue = sqs.Queue(
            self,
            "AlertQueue",
            visibility_timeout=Duration.minutes(2),
            dead_letter_queue=sqs.DeadLetterQueue(max_receive_count=3, queue=alert_dlq),
        )

        ses_config = ses.CfnConfigurationSet(self, "SesConfigurationSet", name="cybertrend")
        render_failures_topic = sns.Topic(self, "SesRenderingFailures")
        sns.Topic(self, "OpsAlerts")
        from_email = cdk.CfnParameter(
            self,
            "SesFromEmail",
            type="String",
            default="security-alerts@example.com",
            description="Verified SES sender address.",
        )
        alert_recipients = cdk.CfnParameter(
            self,
            "AlertRecipients",
            type="String",
            default="analyst@example.com",
            description="Comma-separated immediate alert recipients.",
        )
        digest_recipients = cdk.CfnParameter(
            self,
            "DigestRecipients",
            type="String",
            default="analyst@example.com",
            description="Comma-separated daily digest recipients.",
        )

        lambda_code = lambda_.Code.from_asset(
            str(root),
            bundling=cdk.BundlingOptions(
                image=lambda_.Runtime.PYTHON_3_12.bundling_image,
                command=[
                    "bash",
                    "-c",
                    "pip install -r requirements.txt -t /asset-output "
                    "&& cp -R src/cybertrend /asset-output/cybertrend",
                ],
            ),
        )

        common_env = {
            "APP_ENV": "prod",
            "APP_SECRET_ARN": app_secret.secret_arn,
            "DB_SECRET_ARN": database.secret.secret_arn,
            "SOURCE_QUEUE_URL": ingestion_queue.queue_url,
            "ALERT_QUEUE_URL": alert_queue.queue_url,
            "SES_FROM_EMAIL": from_email.value_as_string,
            "ALERT_RECIPIENTS": alert_recipients.value_as_string,
            "DIGEST_RECIPIENTS": digest_recipients.value_as_string,
            "SES_CONFIGURATION_SET": ses_config.name or "cybertrend",
        }

        common_kwargs = {
            "runtime": lambda_.Runtime.PYTHON_3_12,
            "architecture": lambda_.Architecture.ARM_64,
            "code": lambda_code,
            "timeout": Duration.minutes(5),
            "memory_size": 1024,
            "vpc": vpc,
            "environment": common_env,
        }

        api_fn = lambda_.Function(
            self, "ApiFunction", handler="cybertrend.handlers.api_handler", **common_kwargs
        )
        collector_fn = lambda_.Function(
            self,
            "CollectorFunction",
            handler="cybertrend.handlers.collector_handler",
            **common_kwargs,
        )
        ingestion_fn = lambda_.Function(
            self,
            "IngestionWorkerFunction",
            handler="cybertrend.handlers.ingestion_worker_handler",
            **common_kwargs,
        )
        alert_fn = lambda_.Function(
            self,
            "AlertWorkerFunction",
            handler="cybertrend.handlers.alert_worker_handler",
            **common_kwargs,
        )
        digest_fn = lambda_.Function(
            self, "DigestFunction", handler="cybertrend.handlers.digest_handler", **common_kwargs
        )
        source_quality_fn = lambda_.Function(
            self,
            "SourceQualityFunction",
            handler="cybertrend.handlers.source_quality_handler",
            **common_kwargs,
        )

        ingestion_fn.add_event_source(
            event_sources.SqsEventSource(ingestion_queue, report_batch_item_failures=True)
        )
        alert_fn.add_event_source(
            event_sources.SqsEventSource(alert_queue, report_batch_item_failures=True)
        )

        for fn in [api_fn, collector_fn, ingestion_fn, alert_fn, digest_fn, source_quality_fn]:
            app_secret.grant_read(fn)
            database.secret.grant_read(fn)
            database.connections.allow_default_port_from(fn)
            fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["ses:SendEmail", "ses:SendBulkEmail"],
                    resources=["*"],
                )
            )
        ingestion_queue.grant_send_messages(collector_fn)
        alert_queue.grant_send_messages(ingestion_fn)

        api = apigw.LambdaRestApi(
            self,
            "InternalApi",
            handler=api_fn,
            proxy=True,
            deploy_options=apigw.StageOptions(metrics_enabled=True, tracing_enabled=True),
        )

        scheduler_role = iam.Role(
            self,
            "SchedulerRole",
            assumed_by=iam.ServicePrincipal("scheduler.amazonaws.com"),
        )
        collector_fn.grant_invoke(scheduler_role)
        digest_fn.grant_invoke(scheduler_role)
        source_quality_fn.grant_invoke(scheduler_role)

        scheduler.CfnSchedule(
            self,
            "CollectionSchedule",
            flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(mode="OFF"),
            schedule_expression="rate(15 minutes)",
            target=scheduler.CfnSchedule.TargetProperty(
                arn=collector_fn.function_arn,
                role_arn=scheduler_role.role_arn,
            ),
        )
        scheduler.CfnSchedule(
            self,
            "DailyDigestSchedule",
            flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(mode="OFF"),
            schedule_expression="cron(30 7 * * ? *)",
            schedule_expression_timezone="Europe/London",
            target=scheduler.CfnSchedule.TargetProperty(
                arn=digest_fn.function_arn,
                role_arn=scheduler_role.role_arn,
            ),
        )
        scheduler.CfnSchedule(
            self,
            "WeeklySourceQualitySchedule",
            flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(mode="OFF"),
            schedule_expression="cron(0 8 ? * FRI *)",
            schedule_expression_timezone="Europe/London",
            target=scheduler.CfnSchedule.TargetProperty(
                arn=source_quality_fn.function_arn,
                role_arn=scheduler_role.role_arn,
            ),
        )

        events.Rule(
            self,
            "SesRenderingFailureRule",
            event_pattern=events.EventPattern(source=["aws.ses"]),
            targets=[event_targets.SnsTopic(render_failures_topic)],
        )

        for queue, name in [(ingestion_dlq, "IngestionDlqAlarm"), (alert_dlq, "AlertDlqAlarm")]:
            cloudwatch.Alarm(
                self,
                name,
                metric=queue.metric_approximate_number_of_messages_visible(),
                threshold=1,
                evaluation_periods=1,
            )
        for fn in [collector_fn, ingestion_fn, alert_fn, digest_fn, api_fn]:
            cloudwatch.Alarm(
                self,
                f"{fn.node.id}Errors",
                metric=fn.metric_errors(period=Duration.minutes(5)),
                threshold=1,
                evaluation_periods=1,
            )

        cdk.CfnOutput(self, "ApiUrl", value=api.url)
        cdk.CfnOutput(self, "IngestionQueueUrl", value=ingestion_queue.queue_url)
        cdk.CfnOutput(self, "AlertQueueUrl", value=alert_queue.queue_url)

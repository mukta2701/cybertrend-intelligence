from __future__ import annotations

import aws_cdk as cdk

from infra.cybertrend_stack import CybertrendStack

app = cdk.App()
CybertrendStack(app, "CybertrendStack")
app.synth()

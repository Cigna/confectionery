## Rules
Within this directory we have a collection of standardized AWS and Azure policies used to manage and govern Terraform resources. 

### Conftest
Conftest is a utility to help you write tests against structured configuration data utilizing the Rego language from [Open Policy Agent](https://www.openpolicyagent.org/). 

### Rego
[Rego](https://www.openpolicyagent.org/docs/latest/#rego)(pronounced "ray-go") is a high-level declarative language used for expressing policies over complex hierarchical data structures. Essentially, it is used to create policy that is easy to read and write.

### Regula 
We utilize another library called [Regula](https://github.com/fugue/regula#readme) that evaluates infrastructure-as-code such as Terraform for security and compliance issues. These rules are written in Rego and managed by Fugue.

#### How does it work 
First, it uses a shell script to generate a JSON output for OPA to consume. 

Then, it combines resources from ```planned_values``` and ```configuration``` in the Terraform plan into an accessible format and walks through the imported TF modules then merges them into flat format. 

Next, it looks for rules found in `policy/` directory and executes them against the Terraform plan. Lastly, generates a report with the results of the rules.


## Creating or modifying rules/policies 
``` 
# Collect all sse algorithms configured under `server_side_encryption_configuration`.
used_sse_algorithms[algorithm] {
	algorithm = input.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm
}

deny[msg] {
	# Deny resource if sse algorithm is not configured for s3
	count(used_sse_algorithms) <= 0
	msg = "S3 server-side encryption is required for all s3 buckets."
}
```

Conftest checks for ```deny```, ```violation```, or ```warn``` rules. In the example above we have a deny rule that checks Terraform files for S3 server side encryption enabled. Counting the number of sse algorithms and if it is greater than 0 displaying the deny message.
<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/cigna/confectionery">
    <img src="images/confectionery.png" alt="Logo" width="300" height="160">
  </a>

  <h3 align="center">Confectionery</h3>

  <p align="center">
    A library of rules for Conftest used to detect misconfigurations within Terraform configuration files
    <br />
    <br />
    <a href="https://github.com/cigna/confectionery/issues">Report Bug</a>
    ·
    <a href="https://github.com/cigna/confectionery/issues">Request a New Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->

<h2 style="display: inline-block">Table of Contents</h2>
<ol>
  <li>
    <a href="#confectionery">Confectionery</a>
    <ul>
      <li><a href="#what-is-confectionery">What is Confectionery?</a></li>
    </ul>
  </li>
  <li>
    <a href="#getting-started">Getting Started</a>
    <ul>
      <li><a href="#generating">Generating Plan</a></li>
    </ul>
  </li>
  <li><a href="#creating">Creating Rules</a></li>
  <li><a href="#testing">Testing</a></li>
  <li><a href="#contributing">Contributing</a></li>
  <li><a href="#Original Contributors">Original Contributors</a></li>
</ol>



# Confectionery


## What is Confectionery?

Confectionery is a library of rules for the [Conftest](https://www.conftest.dev/) tool. These rules can be used to detect misconfigurations in Terraform plans and other configuration file formats. The terraform rules also leverage the [Regula](https://github.com/fugue/regula) library to assist with the parsing of Terraform plans. 

By creating rules for the Conftest tool, misconfigurations can be caught earlier in the development cycle by being rule-locally or as part of a CI/CD pipeline. This helps prevent the introduction of the misconfiguration into the runtime environment. For example, you can ensure any resource deployed is on the allowed list of services. 

Confectionery helps enforce governance expectations and provides a fast feedback loop for developers. 

## Getting Started

To use Confectionery you must first [install Conftest](https://www.conftest.dev/install/)

### Generating the terraform plan json

``terraform init``

``terraform plan -out tf-plan.binary ``

``terraform show -json tf-plan.binary > tf-plan.json``


The following command will place the rego rules into a directory called ``policy`` in the directory it is run from. It will then validate the plan. It will only download if the files have changed 

``conftest test --update "git::https://github.com/cigna/confectionery.git//rules/terraform?ref=<tagged-version>" tf-plan.json``

You can override the location the rules are stored with path option below. This should be useful for caching

``conftest test -p test/ --update "git::https://github.com/cigna/confectionery.git//rules/terraform?ref=<tagged-version>" tf-plan.json``

To see available tags please click on [Releases](https://github.com/cigna/confectionery/releases).

### How to Use Exceptions

If it is necessary to temporarily suppress a rule while waiting for a fix to be added to the library, or a non-fixable false-positive exists then exceptions can be used. We have adopted Regula's feature for exceptions which is detailed [here](https://regula.dev/configuration.html#waiving-rule-results).

When using exceptions with Conftest, the `test` command can be modified to the following format

``conftest test -p policy -p exceptions --update "git::https://github.com/cigna/confectionery.git//rules/terraform?ref=<tagged-version>" tf-plan.json``

The additional ``-p`` argument would be used to specify the path to an additional directory which houses the necessary file

A sample ``config.rego`` can be seen below. Multiple rules can be specified, and the waiver/exception can be limited to certain resources. Please refer to the regula link above for the the full list of supported filters. Rule names can be found on the first line of the relevant rule rego file after ``rules.`` in the package name.

```
package fugue.regula.config

waivers[waiver] {
    waiver := {
        "rule_name": "<rule name goes here>",
    } 
} {    
    waiver := {
        "rule_name": "<second rule name here>",
    }
}
```

## Creating Rules
To get started creating rules follow along with this [rules overview](rules/README.md).
## Writing Tests
Please visit our [testing](test-files/README.md) page to learn more about how to get started writing Conftest rules. 
## Contributing
If you would like to contribute please refer to our [contributing guide](CONTRIBUTING.md). Any additions will be much appreciated, please follow these steps:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Original Contributors
Confectionery started as an internal project at Cigna. We would like to recognize the following people for their initial contributions to the project:

- Anthony Barbieri
- Kory Sansom
- Luke Newman
- Kristie Cunha
- Jason Wai
- Matthew Bradley
- Omer Farooq
- Nikiyah Beulah
- Timothy Gorecki
- Gavilan Steinman
- Gabrielle Hempel
- Timothy Morris
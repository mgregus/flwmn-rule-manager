Rule-Manager
============

Rule-Manager is a set of Python CLI scripts that allows for the management of local and remote
rule sources on Flowmon Collector Appliance.

Documentation
=============

`Documentation <https://github.com/mgregus/flwmn-rule-manager/docs>`__ contains both source code documentation and user guide.


Application Overview
====================

Rule Manager is a Python program designed to handle and analyze rule sets used in Intrusion Detection and Prevention Systems (IDPS), such as Suricata and Snort. It provides various functionalities to manage and analyze rule sets effectively.


Features:
  **Rule Statistics:** Rule Manager can provide statistical data about the ruleset, including the number of rules with specific keywords. This helps users gain insights into the composition of their rule sets.

  **Rule Trigger Statistics:** Users can analyze rule hits based on specific key-value pairs, sorted in descending order by the number of rule hits. This feature assists in identifying rules that are frequently triggered.

  **Threshold Generation:** Rule Manager offers the capability to generate threshold commands for creating thresholds for given rules. This functionality aids in fine-tuning rule triggers and optimizing rule sets.

  **Suppress Command Generation:** Users can generate suppress commands to suppress alerts for specific rules. This feature allows users to manage alerts more effectively and reduce noise in the system.

  **Rule Syntax Checking:** Rule Manager includes a syntax checker to validate the syntax of rules in .rules files. This ensures that rules are correctly formatted and comply with the syntax requirements of the IDPS.

  **Rule Enable/Disable:** Users can enable or disable rules based on specific key-value pairs. This allows for dynamic management of rule sets based on changing requirements or conditions.

  **Group Management:** Rule Manager provides functionalities to list all used rule groups, update the list of used rule groups, and set group descriptions. This aids in organizing and managing rule sets efficiently.

  **Output Options:** Users can specify output filenames to write analysis results or rule modifications to files, facilitating further analysis or integration with other tools.


Setup
=====

Install dependencies:
::
    python3 setup.py install

Then add CLI scripts to PATH by running setup.sh:
::
    ./setup.sh

After running setup.sh programm can be run using:
::
    rule-manager -h

If this step is skipped:
::
    python3 manager/rule-manager.py -h




Usage
=====
::

    rule-manager.py [-h] [-s ['<keyword>' or '<keyword> <keyword_value>' ...]] [-r <keyword> <value> <N>]
                           [-t <gid> <sid> <type> <track> count seconds] [-sp <gid> <sid> <track> <ip>] [-f <path>]
                           [-e <keyword> <value>] [-d <keyword> <value>] [-g] [-u] [-l [<groupname>]]
                           [--set-group-description <groupname> <description>] [-ldc] [-c <path>] [-o <filename>]

Rule Manager for handling and analyzing rule sets.

Options:
::

    -h, --help            show this help message and exit

    -s ['<keyword>' or '<keyword> <keyword_value>' ...], --stats ['<keyword>' or '<keyword> <keyword_value>' ...]
                    Shows statistical data about number of rules with given keyword.If none are provided lists all
                    keywords

    -r <keyword> <value> <N>, --rule-trigger-stats <keyword> <value> <N>
                    Shows statistical data about first N number of rule hits with matching key value pair, sorted
                    descending by number of rule hits.

    -t <gid> <sid> <type> <track> count seconds, --generate-threshold <gid> <sid> <type> <track> count seconds
                    Generates threshold command to create threshold for a given rule. You can add the command to
                    threshold config - threshold.conf

    -sp <gid> <sid> <track> <ip>, --generate-supress <gid> <sid> <track> <ip>
                    Generates supress command to supress alerts for a given rule. You can add the command to
                    threshold config - threshold.conf

    -f <path>, --file <path>
                    File to calculate stats on, use with -s, -r. Default -s file /data/idsp/rules/suricata.rules,
                    Default -r file /data/idsp/outputs/eve.json

    -e <keyword> <value>, --enable-category <keyword> <value>
                    Enable rules with matching key-value.

    -d <keyword> <value>, --disable-category <keyword> <value>
                    Disable rules with matching key-value.

    -g, --list-used-groups
                    Return a list of all used rule groups (.rules files).

    -u, --update-used-groups
                    Updates the list of used rule groups in (sourceList.json) based on used rule sources.

    -l [<groupname>], --list-used-groups-long [<groupname>]
                    Return a list of all used rule groups (.rules files) with descriptions from (sourceList.json)

    --set-group-description <groupname> <description>
                    Sets group description in sourceList.json

    -ldc, --list-disabled-categories
                    Return a list of all disabled rule categories

    -c <path>, --check-rules-syntax <path>
                    Checks the syntax of rules in .rules file.

    -o <filename>, --output <filename>
                    Write output to a specified file.

Example usage:
::
  rule-manager -s metadata_keyword metadata_value -f /path/to/file.rules


License
=======

Rule-Manager is licensed under the the `Apache License, Version 2.0 <https://github.com/secureworks/aristotle/blob/master/LICENSE>`__.

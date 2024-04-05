#!/usr/bin/env python3
"""
 * Copyright 2001-2024 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""


import sys
import signal
import argparse
from colorama import Fore, Style

#local files
import paths
import rule_trigger
import activation
import program_expcetion
import stats
import list_disabled
import syntax_check
import rule_sources2


class OutputRedirector:
    """
        A class used to redirect output of program to a specified file instead of stdout
        ...

        Methods
        -------
        __init__(output_file)
            Initializes data.

        write(text)
            Writes output to a given file.

        flush()
            Overrides class flush function.
    """
    def __init__(self, output_file):
        self.output_file = output_file

    def write(self, text):
        with open(self.output_file, 'a') as f:
            f.write(text)

    def flush(self):
        pass

def get_parser():
    """Command line argument parser. Parses input from user and then ensures the program executes the corresponding action.

       Returns
       -------
       parser: argparse.ArgumentParser
           Returns created argument parser.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Rule Manager for handling and analyzing rule sets.",
        epilog="Example usage: rule-manager -s keyword -f /path/to/file.rules"
    )

    parser.add_argument("-s", "--stats",
                        nargs='*',
                        dest="stats_keyword_val",
                        metavar=('\'<keyword>\' or \'<keyword> <keyword_value>\''),
                        required=False,
                        help="Shows statistical data about number of rules with given keyword."
                             "If none are provided lists all keywords")

    parser.add_argument("-r", "--rule-trigger-stats",
                        nargs=3,
                        dest="rule_trigger",
                        metavar=('<keyword>', '<value>', '<N>'),
                        help="Shows statistical data about first N number of rule hits "
                             "with matching key value pair, sorted descending by number of rule hits.")

    parser.add_argument("-t", "--generate-threshold",
                        nargs=6,
                        dest="threshold",
                        metavar=('<gid>', '<sid>', '<type>','<track>','count','seconds'),
                        help="Generates threshold command to create threshold for a given rule. "
                             "You can add the command to threshold config - threshold.conf")

    parser.add_argument("-sp", "--generate-supress",
                        nargs=4,
                        dest="supress",
                        metavar=('<gid>', '<sid>', '<track>', '<ip>'),
                        help="Generates supress command to supress alerts for a given rule. "
                             "You can add the command to threshold config - threshold.conf")

    parser.add_argument("-f", "--file",
                        dest="file_path",
                        nargs=1,
                        metavar=('<path>'),
                        help="File to calculate stats on, use with -s, -r. "
                             "Default -s file /data/idsp/rules/suricata.rules, "
                             "Default -r file /data/idsp/outputs/eve.json")

    parser.add_argument("-e", "--enable-category",
                        nargs=2,
                        dest="enable_category",
                        metavar=('<keyword>', '<value>'),
                        help="Enable rules with matching key-value.")

    parser.add_argument("-d", "--disable-category",
                        nargs=2,
                        dest="disable_category",
                        metavar=('<keyword>', '<value>'),
                        help="Disable rules with matching key-value.")

    parser.add_argument("-g", "--list-used-groups",
                        action="store_true",
                        help="Return a list of all used rule groups (.rules files).")

    parser.add_argument("-u", "--update-used-groups",
                        action="store_true",
                        help="Updates the list of used rule groups in (sourceList.json) "
                             "based on used rule sources.")

    parser.add_argument("-l", "--list-used-groups-long",
                        const="*",
                        nargs='?',
                        metavar=('<groupname>'),
                        help="Return a list of all used rule groups (.rules files) "
                             "with descriptions from (sourceList.json)")

    parser.add_argument("--set-group-description",
                        nargs=2,
                        metavar=('<groupname>', '<description>'),
                        help="Sets group description in sourceList.json")

    parser.add_argument("-ldc","--list-disabled-categories",
                        action="store_true",
                        dest="disabled_cats",
                        default=None,
                        help="Return a list of all disabled rule categories")

    parser.add_argument("-c", "--check-rules-syntax",
                        nargs=1,
                        dest="syntax_check",
                        metavar=('<path>'),
                        help="Checks the syntax of rules in .rules file.")

    parser.add_argument("-o", "--output",
                        nargs=1,
                        dest="outfile",
                        default=None,
                        metavar=('<filename>'),
                        help="Write output to a specified file.")

    return parser


def _main():
    """Hanles argument parsing from command line user input to program and calls corresponding functions. From each module.

    """
    try:
        parser = get_parser()
        args = parser.parse_args()

        if args.outfile:
            output_file = args.outfile[0]
            sys.stdout = OutputRedirector(output_file)

        if args.stats_keyword_val is not None:
            stats.analyze_ruleset(args.stats_keyword_val, args.file_path)

        if args.enable_category is not None:
            activation.manage_category(args.enable_category, False)

        if args.disable_category is not None:
            activation.manage_category(args.disable_category, True)

        if args.rule_trigger is not None:
            rule_trigger.calculate_stats(args.rule_trigger, args.file_path)

        if args.syntax_check is not None:
            syntax_check.check_rule_syntax(args.syntax_check)

        if args.disabled_cats is not None:
            list_disabled.list_disabled_categories()

        if args.threshold is not None:
            rule_trigger.generate_threshold_command(args.threshold)

        if args.supress is not None:
            rule_trigger.generate_supress_command(args.supress)

        if args.list_used_groups:
            rule_sources2.print_used_groups()

        if args.list_used_groups_long:
            rule_sources2.print_used_groups(args.list_used_groups_long,True)

        if args.set_group_description:
            rule_sources2.update_group_description(args.set_group_description)

        if args.update_used_groups:
            rule_sources2.update_group_config()

        sys.stdout = sys.__stdout__

    except Exception as e:
        program_expcetion.log_error(e)
        error_msg = f"{Fore.RED}Program run into unexpected failure!{Style.RESET_ALL}\n"
        error_msg += f"For more information checkout ERROR LOG file \'{paths.ERROR_LOG}\'\n"

        print(error_msg)

def signal_handler(signal, frame):
    print('Program interrupted. Aborting...')
    sys.exit(1)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    try:
        sys.exit(_main())
    except Exception as err:
        print(err)
    sys.exit(1)

if __name__ == '__main__':
    main()

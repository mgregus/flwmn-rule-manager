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


import paths
from colorama import Style, Fore


def extract_disabled_stuff():
    """Gets information about disabled rule categories from disable.conf

    Separates disabled rules into categories based on the disabling attribute:

        1. 'group:' <=> disabled group of rules
        2. 're:classtype:' <=> disabled rules based on classtype value
        3. 'metdatata' <=> disabled rules based on metadata key value
        4. 're:' <=> disabled rules which fit regular expression specified
    """
    disabled_groups = []
    disabled_metadata = []
    disabled_classtype = []
    other_disabled = []

    with open(paths.DISABLE_CONF, 'r') as file:
        for line in file:
            line = line.strip()

            if line.startswith('#') or len(line) == 0:
                continue
            elif line.startswith('group:'):
                disabled_groups.append(line)
            elif line.startswith('metadata:'):
                disabled_metadata.append(line)
            elif line.startswith('re:classtype:'):
                disabled_classtype.append(line)
            else:
                other_disabled.append(line)
    return disabled_groups, disabled_metadata, disabled_classtype, other_disabled



def print_disabled_cats(categories):
    """Prints disabled rule groups inside a given category.
    """
    for disabled_cat in categories:
        print(f'\t\t{disabled_cat}')
    return

def list_disabled_categories():
    """Prints all disabled rule categories based on the contents of disable.conf.

        Lists disabled rule categories:

            1. disabled rule categories based on group name

            2. disabled rule categories based on classtype value

            3. disabled rule categories based on metadata attributes

            4. disabled rule categories based on other reggex attributes specified in disable.conf

    """
    disabled_groups, disabled_metadata, disabled_classtype, other_disabled = extract_disabled_stuff()

    print(f"{Fore.GREEN}Listing disabled rule categories: {Style.RESET_ALL}")

    print(f"\t{Fore.BLUE}Disabled Groups:{Style.RESET_ALL}")
    print_disabled_cats(disabled_groups)

    print(f"\n\t{Fore.BLUE}Disabled Metadata:{Style.RESET_ALL}")
    print_disabled_cats(disabled_metadata)

    print(f"\n\t{Fore.BLUE}Disabled Classtypes:{Style.RESET_ALL}")
    print_disabled_cats(disabled_classtype)

    print(f"\n\t{Fore.BLUE}Other disabled rule categories:{Style.RESET_ALL}")
    print_disabled_cats(other_disabled)
    print("")

    return
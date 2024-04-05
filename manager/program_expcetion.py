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

import os
import datetime
import paths
import traceback

def log_error(exception):
    """Logs exception raised during the program execution to the error.log along with the stack trace and current
       date and time.

        Error.log is used to store exception logs and error logs encountered by the programm along with stack traces.

       Parameters
       ----------
       exception : Exception
            Exception raised during program execution.
        """
    error_log_file = f"{paths.ERROR_LOG}"
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    create_error_log()

    try:
        with open(error_log_file, "a") as file:
            file.write(f"{current_time}: {exception}\n")
            file.write("Stack Trace:\n")
            traceback.print_tb(exception.__traceback__, file=file)
            file.write("\n\n")
    except Exception as e:
        print(f"Error occurred while writing to error log: {e}")

def create_error_log():
    """Creates a program error.log file if it does not already exist.

    Error.log is used to store exception logs and error logs encountered by the programm along with stack traces.

    """
    error_log_file = f"{paths.ERROR_LOG}\n"

    try:
        if not os.path.exists(error_log_file):
            with open(error_log_file, "w") as file:
                file.write("Error Log\n")
    except Exception as e:
        print(f"Error occurred while creating error log: {e}")

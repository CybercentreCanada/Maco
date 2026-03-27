"""Helper functions to help generating specific objects from model.py"""

import re
import logging
from maco.model import ScheduledTask
from typing import Optional


logger = logging.getLogger("maco.lib.helpers")

# --------------------------------------------------------
# Functions to help generating the 'ScheduledTask' object.
# --------------------------------------------------------
def replace_control_chars_with_escapes(string: str) -> str:
    """
    This function replaces control characters in a string with their corresponding escape sequences.
    It is useful for preserving common Windows path escape sequences when control characters have been
    pre-interpreted during the parsing of the command string.

    Input: C:\Windows\System32\narrator.exe
    Not escaped: C:\Windows\System32arrator.exe
    Escaped: C:\Windows\System32\narrator.exe

    Args:
        string (str): The input string to process.

    Returns:
        str: The string with the control characters replaced by escape sequences.
    """
    return string.translate(
        {
            ord("\b"): r"\b",
            ord("\t"): r"\t",
            ord("\n"): r"\n",
            ord("\r"): r"\r",
            ord("\f"): r"\f",
            ord("\v"): r"\v",
        }
    )


def search_field_using_regex(cmd: str, pattern: str, data_type: int) -> Optional[str|int]:
    """
    This function searches for a field in the command string using a regex pattern. It simplifies
    the process of extracting values from the input string based on specific patterns.

    Arguments:
        cmd (str): The command string to search.
        pattern (str): The regex pattern to use for searching.
        data_type (int): The type of data to extract:
            0: existence,
            1: option with no value
            2: option with value
            3: option with value that can also be empty

    Returns:
        Optional[str|int]: The extracted value if found, otherwise None.
    """
    match = re.search(pattern, cmd)

    if match:
        if data_type == 0:
            # Detecting the existence of an option.
            return match.end()
        elif data_type == 1:
            # Option with no value (Ex. /Create).
            return match.group(1)
        elif data_type == 2:
            # Option with a value.
            return replace_control_chars_with_escapes(match.group(1) or match.group(2))
        elif data_type == 3:
            # Option with a value that can be empty (Ex. /tr).
            return replace_control_chars_with_escapes(match.group(1) or match.group(2) or "")

    return None


def parse_scheduled_task_command(cmd: str) -> Optional[ScheduledTask]:
    """
    Parse a scheduled task command string into its components. This function simplifies the process of
    generating a ScheduledTask object from a command string.

    Args:
        command (str): The task scheduler command to parse (Ex.'schtasks /Create /tn "My Task" /tr "C:\\Program Files\\MyApp\\app.exe" /sc daily').

    Returns:
        ScheduledTaskCommand: The parsed command stored as a ScheduledTask object or None if malformated.
    """
    st = ScheduledTask()
    st.raw_command = cmd
    logger.debug(f"------------------\nScheduledTask:\n{cmd}\n------------------")

    # --------------------
    # Step 1: Identify the task scheduler command (optionally with a full path). [REQUIRED]
    # --------------------
    schtasks = search_field_using_regex(cmd, r"(?i)(?:^|[\\/\s])schtasks(?:\.exe)?(?=\s|$)", 0) is not None
    if not schtasks: return None

    # --------------------
    # Step 2: Extract the task type that follows the schtasks command (Ex. /Create, /END, /rUn). [REQUIRED]
    # --------------------
    task_type = search_field_using_regex(cmd, r"(?i)\/(create|change|delete|end|run|query)(?=\s|$)", 1)
    if task_type:
        try: st.task_type = st.TaskOperationEnum(task_type.upper())
        except ValueError: return None # Invalid task type, required so return.
    else: return None
    logger.debug(f"\ttask_type: {st.task_type}")

    # --------------------
    # Step 3: Extract the task name from '/tn <taskname>' or '/tn "<taskname>"'. [OPT in QUERY]
    # --------------------
    st.task_name = search_field_using_regex(cmd, r'(?i)(?:^|\s)/tn\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\ttask_name: {st.task_name}")

    # --------------------
    # Step 4: Extract the task schedule type from '/sc <scheduleType>' [OPT]
    # --------------------
    schedule_type = search_field_using_regex(cmd, r'(?i)(?:^|\s)/sc\s+(?:"([^"]+)"|(\S+))', 2)
    if schedule_type:
        try: st.schedule_type = st.ScheduledTypeEnum(schedule_type.upper())
        except ValueError: pass # Invalid task type, ignore.
    logger.debug(f"\tschedule_type: {st.schedule_type}")

    # --------------------
    # Step 5: Extract the task modifier from '/mo <modifier>' [OPT]
    # --------------------
    st.modifier = search_field_using_regex(cmd, r'(?i)(?:^|\s)/mo\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tmodifier: {st.modifier}")

    # --------------------
    # Step 6: Extract the task day from '/d <day>' [OPT]
    # --------------------
    st.day = search_field_using_regex(cmd, r'(?i)(?:^|\s)/d\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tday: {st.day}")

    # --------------------
    # Step 7: Extract the task month from '/m <month>' [OPT]
    # --------------------
    st.month = search_field_using_regex(cmd, r'(?i)(?:^|\s)/m\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tmonth: {st.month}")

    # --------------------
    # Step 8: Extract the task run from '/tr <run>' or '/tr "<run>"' [OPT]
    # --------------------
    st.task_run = search_field_using_regex(cmd, r'(?i)(?:^|\s)/tr(?:\s+(?:"([^"]*)"|([^/\s][^\s]*)))?', 3)
    logger.debug(f"\ttask_run: {st.task_run}")

    # --------------------
    # Step 9: Extract the task start time from '/st <starttime>' [OPT]
    # --------------------
    st.start_time = search_field_using_regex(cmd, r'(?i)(?:^|\s)/st\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tstart_time: {st.start_time}")

    # --------------------
    # Step 10: Extract the task end time from '/et <endtime>' [OPT]
    # --------------------
    st.end_time = search_field_using_regex(cmd, r'(?i)(?:^|\s)/et\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tend_time: {st.end_time}")

    # --------------------
    # Step 11: Extract the task duration from '/du <duration>' [OPT]
    # --------------------
    st.duration = search_field_using_regex(cmd, r'(?i)(?:^|\s)/du\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tduration: {st.duration}")

    # --------------------
    # Step 12: Extract the flag (/k) that stops the program that the task runs at the time specified by
    # /et or /du. [OPT]
    # --------------------
    st.k = search_field_using_regex(cmd, r"(?i)(?:^|\s)/k(?=\s|$)", 0) is not None
    logger.debug(f"\tterminate_if_runs_longer: {st.k}")

    # --------------------
    # Step 13: Extract the task start date from '/sd <startdate>' [OPT]
    # --------------------
    st.start_date = search_field_using_regex(cmd, r'(?i)(?:^|\s)/sd\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tstart_date: {st.start_date}")

    # --------------------
    # Step 14: Extract the task end date from '/ed <enddate>' [OPT]
    # --------------------
    st.end_date = search_field_using_regex(cmd, r'(?i)(?:^|\s)/ed\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tend_date: {st.end_date}")

    # --------------------
    # Step 15: Extract the interval for repeating a task from '/ri <interval>' [OPT]
    # --------------------
    st.interval = search_field_using_regex(cmd, r'(?i)(?:^|\s)/ri\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tinterval: {st.interval}")

    # --------------------
    # Step 16: Extract the idle time before running the task from '/i <idletime>' [OPT]
    # --------------------
    st.idle_time = search_field_using_regex(cmd, r'(?i)(?:^|\s)/i\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tidle_time: {st.idle_time}")

    # --------------------
    # Step 17: Extract the delay time to wait from '/delay <delaytime>' [OPT]
    # --------------------
    st.delay_time = search_field_using_regex(cmd, r'(?i)(?:^|\s)/delay\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tdelay_time: {st.delay_time}")

    # --------------------
    # Step 18: Extract the run level from '/rl <level>' [OPT]
    # --------------------
    run_level = search_field_using_regex(cmd, r'(?i)(?:^|\s)/rl\s+(?:"([^"]+)"|(\S+))', 2)
    if run_level:
        try: st.run_level = st.RunLevelEnum(run_level.upper())
        except ValueError: pass # Invalid task type, ignore.
    logger.debug(f"\trun_level: {st.run_level}")

    # --------------------
    # Step 19: Extract the remote computer from '/s <computer>' [OPT]
    # --------------------
    st.remote_computer = search_field_using_regex(cmd, r'(?i)(?:^|\s)/s\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tremote_computer: {st.remote_computer}")

    # --------------------
    # Step 20: Extract the user account domain from '/u [<domain>\]<user>' [OPT]
    # --------------------
    user_account = search_field_using_regex(cmd, r'(?i)(?:^|\s)/u\s+(?:"([^"]+)"|(\S+))', 2)
    if user_account:
        if "\\" in user_account:
            st.user_domain, st.user_account = user_account.split("\\", 1)
        else:
            st.user_account = user_account
    logger.debug(f"\tuser_domain: {st.user_domain}")
    logger.debug(f"\tuser_account: {st.user_account}")

    # --------------------
    # Step 21: Extract the password for the user account from '/p <password>' [OPT]
    # --------------------
    st.user_password = search_field_using_regex(cmd, r'(?i)(?:^|\s)/p\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tuser_password: {st.user_password}")

    # --------------------
    # Step 22: Extract the account to run the task as from '/ru {[<domain>\]<user> | system}' [OPT]
    # --------------------
    run_as_account = search_field_using_regex(cmd, r'(?i)(?:^|\s)/ru\s+(?:"([^"]+)"|(\S+))', 2)
    if run_as_account:
        if run_as_account.lower() == "system":
            st.run_as = st.RunAsEnum.system
        else:
            st.run_as = st.RunAsEnum.user
            if "\\" in run_as_account:
                st.run_as_domain, st.run_as_user = run_as_account.split("\\", 1)
            else:
                st.run_as_user = run_as_account
    logger.debug(f"\trun_as: {st.run_as}")
    logger.debug(f"\trun_as_domain: {st.run_as_domain}")
    logger.debug(f"\trun_as_user: {st.run_as_user}")

    # --------------------
    # Step 23: Extract the password for the account to run the task as from '/rp <password>' [OPT]
    # --------------------
    st.run_as_password = search_field_using_regex(cmd, r'(?i)(?:^|\s)/rp\s+(?:"([^"]+)"|(\S+))', 3)
    logger.debug(f"\trun_as_password: {st.run_as_password}")

    # --------------------
    # Step 24: Extract the channel name for an event-based task from '/ec <channelname>' [OPT]
    # --------------------
    st.channel_name = search_field_using_regex(cmd, r'(?i)(?:^|\s)/ec\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\tchannel_name: {st.channel_name}")

    # --------------------
    # Step 25: Extract the flag (/it) to run the task only when the user is logged on interactively. [OPT]
    # --------------------
    st.interactive = search_field_using_regex(cmd, r'(?i)(?:^|\s)/it\b', 0) is not None
    logger.debug(f"\tinteractive: {st.interactive}")

    # --------------------
    # Step 26: Extract the flag (/np) to specify that the task does not require a password. [OPT]
    # --------------------
    st.no_password = search_field_using_regex(cmd, r'(?i)(?:^|\s)/np\b', 0) is not None
    logger.debug(f"\tno_password: {st.no_password}")

    # --------------------
    # Step 27: Extract the flag (/z) to specify that the task will be deleted after it runs. [OPT]
    # --------------------
    st.auto_delete = search_field_using_regex(cmd, r'(?i)(?:^|\s)/z\b', 0) is not None
    logger.debug(f"\tauto_delete: {st.auto_delete}")

    # --------------------
    # Step 28: Extract the XML file for the task definition from '/xml <xmlfile>' [OPT]
    # --------------------
    st.xml = search_field_using_regex(cmd, r'(?i)(?:^|\s)/xml\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\txml: {st.xml}")

    # --------------------
    # Step 29: Extract the flag (/v1) that specifies the task should be created using the version 1
    # task scheduler. [OPT]
    # --------------------
    st.v1 = search_field_using_regex(cmd, r'(?i)(?:^|\s)/v1\b', 0) is not None
    logger.debug(f"\tv1: {st.v1}")

    # --------------------
    # Step 30: Extract the flag (/f) to specify to create/delete the task and suppress warnings. [OPT]
    # --------------------
    st.force = search_field_using_regex(cmd, r'(?i)(?:^|\s)/f\b', 0) is not None
    logger.debug(f"\tforce: {st.force}")

    # --------------------
    # Step 31: Extract the hresult from '/hresult <hresult>' [OPT]
    # --------------------
    st.hresult = search_field_using_regex(cmd, r'(?i)(?:^|\s)/hresult\s+(?:"([^"]+)"|(\S+))', 2)
    logger.debug(f"\thresult: {st.hresult}")

    # --------------------
    # Step 32: Extract the output format for a query from '/fo {TABLE | LIST | CSV}' [REQ in QUERY]
    # --------------------
    output_format = search_field_using_regex(cmd, r'(?i)(?:^|\s)/fo\s+(?:"([^"]+)"|(\S+))', 2)
    if output_format:
        try: st.output_format = st.OutputFormatEnum(output_format.upper())
        except ValueError: pass # Invalid output format, ignore.
    logger.debug(f"\toutput_format: {st.output_format}")

    # --------------------
    # Step 33: Extract the flag (/nh) to specify whether to display column headers in the output (TABLE). [OPT]
    # --------------------
    st.no_header = search_field_using_regex(cmd, r'(?i)(?:^|\s)/nh\b', 0) is not None
    logger.debug(f"\tno_header: {st.no_header}")

    # --------------------
    # Step 34: Extract the flag (/v) to display all properties of the scheduled tasks in the output
    # (TABLE / LIST). [OPT]
    # --------------------
    st.add_advanced_properties = search_field_using_regex(cmd, r'(?i)(?:^|\s)/v\b', 0) is not None
    logger.debug(f"\tadd_advanced_properties: {st.add_advanced_properties}")

    return st

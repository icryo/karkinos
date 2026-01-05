import sys
from mythic_container.MythicCommandBase import (
    TaskArguments,
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    ParameterGroupInfo,
    SupportedOS,
    MythicTask,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
    BrowserScript,
)
from mythic_container.MythicGoRPC import (
    SendMythicRPCFileSearch,
    MythicRPCFileSearchMessage,
)


class BofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="BOF/COFF file to execute (.o file compiled for x64)",
                display_name="BOF File",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments in Cobalt Strike format (see help for syntax)",
                display_name="Arguments",
                default_value="",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=2,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="entry_point",
                type=ParameterType.String,
                description="Entry point function name (default: go)",
                display_name="Entry Point",
                default_value="go",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=3,
                        required=False,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class BofCommand(CommandBase):
    cmd = "bof"
    needs_admin = False
    help_cmd = "bof"
    description = """Execute a Beacon Object File (BOF) in-memory.

BOFs are small compiled C programs that run inside the agent's process space.
They are loaded and executed without spawning a new process or writing to disk.

ARGUMENT FORMAT (Cobalt Strike compatible):
  short:VALUE or s:VALUE  - 16-bit signed integer
  int:VALUE or i:VALUE    - 32-bit signed integer
  str:VALUE or z:VALUE    - Null-terminated ASCII string
  wstr:VALUE or Z:VALUE   - Null-terminated wide (UTF-16) string
  bin:BASE64 or b:BASE64  - Binary data (base64 encoded)

EXAMPLES:
  bof whoami.x64.o
  bof dir.x64.o wstr:"C:\\Windows\\System32"
  bof enum_users.x64.o str:DOMAIN
  bof inject.x64.o int:1234 bin:c2hlbGxjb2Rl

NOTES:
  - BOFs must be compiled for the correct architecture (x64)
  - Default entry point is 'go', override with entry_point parameter
  - This command is Windows-only
"""
    version = 1
    is_file_upload = True
    author = "@thanatos"
    attackmapping = ["T1106"]  # Native API
    argument_class = BofArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )
    browser_script = BrowserScript(
        script_name="bof",
        author="@thanatos",
        for_new_ui=True,
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        try:
            file_id = task.args.get_arg("file")

            # Get file metadata from Mythic
            resp = await SendMythicRPCFileSearch(
                MythicRPCFileSearchMessage(
                    TaskID=task.id,
                    AgentFileId=file_id,
                )
            )

            if not resp.Success:
                raise Exception(resp.Error)

            if len(resp.Files) == 0:
                raise Exception("File not found")

            file_name = resp.Files[0].Filename
            args = task.args.get_arg("arguments") or ""
            entry = task.args.get_arg("entry_point") or "go"

            # Build display string
            task.display_params = f"{file_name}"
            if args:
                task.display_params += f" {args}"
            if entry != "go":
                task.display_params += f" (entry: {entry})"

            return task

        except Exception as e:
            raise Exception(
                f"Error: {str(e)} (line {sys.exc_info()[-1].tb_lineno})"
            )

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        pass

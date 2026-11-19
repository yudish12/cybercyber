import rewardkit as rk
from pathlib import Path

rk.command_succeeds(cmd=f"bash {Path(__file__).parent / 'behavior.sh'}", timeout=600)

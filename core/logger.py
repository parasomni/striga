import time
from datetime import datetime

class Logger:
    def __init__(self):
        from core import config, check_dir
        self.log_path = config.get_config_value("location", "framework") + '/' + config.get_config_value("logging_dir", "framework")
        self.log_file = self.log_path + '/' + config.get_config_value("logging_file", "framework")
        check_dir(self.log_path)

    def get_formatted_log(self, log):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = f'({current_date_time}) {log} \n'
        return log

    def log(self, log):
        formatted_log = self.get_formatted_log(log)
        print(log)

        with open(self.log_file, "a") as f:
            f.write(formatted_log)
        f.close()
    
    def debug(self, log):
        from core import config
        if not config.debug:
            return
        
        debug_log = self.get_formatted_log(log)
        print(log)
        with open(self.log_file, "a") as f:
            f.write(debug_log)
        f.close()

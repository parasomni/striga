from datetime import datetime

class Logger:
    def __init__(self):
        pass

    def _log_file(self):
        # Computed per-call (not cached at __init__) because scan_id isn't known
        # yet when Logger is constructed -- it's set later, in run_striga(), and
        # can change again on --continue/--continue-scanid. Recomputing here means
        # every scan_id gets its own framework.log instead of one shared file for
        # every run ever.
        from core import config, check_dir
        log_dir = config.frm_path + '/' + config.scan_id + '/' + config.get_config_value("logging_dir", "framework")
        check_dir(log_dir)
        return log_dir + '/' + config.get_config_value("logging_file", "framework")

    def get_formatted_log(self, log):
        current_date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = f'({current_date_time}) {log} \n'
        return log

    def log(self, log):
        formatted_log = self.get_formatted_log(log)
        print(log)

        with open(self._log_file(), "a") as f:
            f.write(formatted_log)

    def debug(self, log):
        from core import config
        if not config.debug:
            return

        debug_log = self.get_formatted_log(log)
        print(log)
        with open(self._log_file(), "a") as f:
            f.write(debug_log)

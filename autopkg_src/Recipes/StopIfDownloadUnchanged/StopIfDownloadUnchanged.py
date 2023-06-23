#!/usr/local/autopkg/python
# Created 06/22/23; NRJA

import threading

from autopkglib import Processor

__all__ = ["StopIfDownloadUnchanged"]


class StopIfDownloadUnchanged(Processor):
    description = (
        "Aborts a recipe run if download_changed value is defined and set to False"
    )
    input_variables = {}

    output_variables = {
        "stop_processing_recipe": {"description": "Bool to stop eval of recipe"}
    }
    __doc__ = description

    def get_download_changed(self):
        """Loops until AutoPkg env download_changed is defined
        If defined as False, sets AutoPkg env stop_processing_recipe
        to True, aborting the current recipe run"""
        while self.download_changed is None:
            try:
                self.download_changed = self.env["download_changed"]
                if self.download_changed == False:
                    self.env["stop_processing_recipe"] = True
            except KeyError:
                continue

    def main(self):
        """Sets initial DL changed value to None
        Sets get_download_changed func as bg func
        Starts it to run in parallels with AutoPkg recipe execution"""
        self.download_changed = None
        bg_thread = threading.Thread(target=self.get_download_changed)
        bg_thread.start()


if __name__ == "__main__":
    processor = StopIfDownloadUnchanged()
    processor.execute_shell()

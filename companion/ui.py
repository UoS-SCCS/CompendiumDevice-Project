#!/usr/bin/env python
from multiprocessing import Queue
import socket
from abc import ABC
class UI():
    @staticmethod
    def get_user_input(q:Queue):
        #We import here to force the import after the fork to save memory usage
        import tkinter as tk
        from tkinter import simpledialog
        root = tk.Tk()
        root.overrideredirect(1)
        root.withdraw()
        id = simpledialog.askstring("Compendium Setup","Compendium is running for the first time. Please enter a name for this device or accept the default hostname", initialvalue=socket.gethostname())
        q.put(id)

#class IDDialog(simpledialog.SimpleDialog):

    # override buttonbox() to create your action buttons
    #def buttonbox(self):
    #    box = tk.Frame(self)
    #    # note that self.ok() and self.cancel() are defined inside `Dialog` class
    #    tk.Button(box, text="Ok", width=10, command=self.ok, default=tk.ACTIVE).pack(side=tk.LEFT, padx=5, pady=5)
    #    self.bind("<Return>", self.ok)
    #    box.pack()



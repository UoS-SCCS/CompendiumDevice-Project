#!/usr/bin/env python
from multiprocessing import Queue
from multiprocessing import Process, Queue
import threading
import socket
import time
from abc import ABC

class QRMonitor():
    def __init__(self,q:Queue,p:Process,callback):
        self.q = q
        self.process = p
        self.callback = callback
        self.mthread = threading.Thread(target=self.monitor_queue,daemon=True)
        self.mthread.start()
    def close(self):
        self.process.terminate()
        self.q.put("Ended")
    
    def monitor_queue(self):
        result = self.q.get()
        if result == "Closed":
            self.process.terminate()
            self.callback(-1)
        


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
    
    @staticmethod
    def show_qr_code(q:Queue, data:str):
        
        import tkinter as tk
        from tkinter import simpledialog, Canvas
        import qrcode
        import PIL
        from PIL import ImageTk, Image
        root = tk.Tk()
        root.title("Compendium Enrolment Screen")

        
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=4,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        qr_image=qr.make_image(fill_color="black", back_color="white")
        qr_image.save("testqr.png")
        root.geometry('800x600')
        canvas = Canvas(root,width=799,height=599,bg="LightBlue")
        canvas.create_text(400, 20, text="Scan this QRCode on your Compendium App to Enrol the Device", fill="black", font=('Helvetica 15 bold'))
        
        image = ImageTk.PhotoImage(qr_image)
        imagesprite = canvas.create_image(400,300,image=image)
        canvas.pack()
        root.mainloop()
        q.put("Closed")
    
    @staticmethod
    def show_qr_screen_new_process(data:str,callback)->QRMonitor:

        q = Queue()
        p = Process(target=UI.show_qr_code, args=(q,data,))
        monitor = QRMonitor(q,p,callback)
        p.start()
        return monitor

        
def test_callback(res):
    print("Callback: %s", res)
if __name__ == "__main__":
    msg = '{"adr_pc": "testAdr", "pc_public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCSLFSb1Ls7Pq1Z5jIPmyiA91WQm\nFdRyKMm5mDb7NkKgM8V/iUOzIIJVaYMkdxsUAfJoZ015FQI9M/nSvAuiEQ==\n-----END PUBLIC KEY-----\n", "g_to_x": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMO8tWaxT0wKCbXnTwMy8cvU4ZCUU\nhjmQ4W5Z/K4fUKqqEHv7wI6iKEN6TBq/7fyhMuMqGH1GB9omBl3yPW84xg==\n-----END PUBLIC KEY-----\n", "signature_pc": "MEYCIQCrVmlbRPPqCRCldSb89CXjzTEmszOtusXCeS11uazBIgIhAJIvCkBGLj3Ny46gTiXL206R\nvRj5S84Sp80QjyBCLj0n\n"}'
    monitor = UI.show_qr_screen_new_process(msg,test_callback)
    time.sleep(10)
    monitor.close()
    print("here")
    #UI.show_qr_code(None, msg)
#class IDDialog(simpledialog.SimpleDialog):

    # override buttonbox() to create your action buttons
    #def buttonbox(self):
    #    box = tk.Frame(self)
    #    # note that self.ok() and self.cancel() are defined inside `Dialog` class
    #    tk.Button(box, text="Ok", width=10, command=self.ok, default=tk.ACTIVE).pack(side=tk.LEFT, padx=5, pady=5)
    #    self.bind("<Return>", self.ok)
    #    box.pack()



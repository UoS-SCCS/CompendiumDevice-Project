"""
 © Copyright 2021-2022 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
import socket
import threading
import time
from abc import ABC

from multiprocessing import Process, Queue


class QRMonitor():
    """QRMonitor provides a class to maintain a reference to the child
    process used for displaying the QRCode. This allows the original
    caller to subsequently shutdown the UI once a response has been 
    received and for the caller to be notified of the user closing
    the window.
    """
    def __init__(self, q: Queue, p: Process, callback):
        """Initialise a new monitor

        Monitor the queue on a new thread waiting for any messages.

        Args:
            q (Queue): used to exchange messages
            p (Process): child process used to run the UI method
            callback (function): callback called when the window is closed
        """
        self.q = q
        self.process = p
        self.callback = callback
        self.mthread = threading.Thread(target=self.monitor_queue, daemon=True)
        self.mthread.start()

    def close(self):
        """Close the UI by terminating the child process
        """
        self.process.terminate()
        self.q.put("Ended")

    def monitor_queue(self):
        """Monitor the queue for notifications that the window has
        been closed and then fire the callback
        """
        result = self.q.get()
        if result == "Closed":
            self.process.terminate()
            self.callback(-1)


class UI():
    @staticmethod
    def get_user_input(q: Queue):
        """Deprecated, we no longer need user input for the PC name

        Args:
            q (Queue): _description_
        """
        # We import here to force the import after the fork to save memory usage
        import tkinter as tk
        from tkinter import simpledialog
        root = tk.Tk()
        root.overrideredirect(1)
        root.withdraw()
        id = simpledialog.askstring(
            "Compendium Setup", "Compendium is running for the first time. Please enter a name for this device or accept the default hostname", initialvalue=socket.gethostname())
        q.put(id)

    @staticmethod
    def show_qr_code(q: Queue, data: str):
        """Shows a window containing a QRCode that has the provided
        data in it. This must be called in a child process, not just
        a new thread as it will take control of the main thread.
        
        The QRCode will be generated with qrcode library and
        PIL. Note we use late binding to avoid importing the
        Tk functionality into the parent process.

        Args:
            q (Queue): queue to exchange messages between processes
            data (str): QRCode data
        """
        import tkinter as tk
        from tkinter import Canvas, simpledialog

        import PIL
        import qrcode
        from PIL import Image, ImageTk
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
        qr_image = qr.make_image(fill_color="black", back_color="white")
        #TODO remove debug saving of qrcode
        qr_image.save("testqr.png")
        root.geometry('800x600')
        canvas = Canvas(root, width=799, height=599, bg="LightBlue")
        canvas.create_text(400, 20, text="Scan this QRCode on your Compendium App to Enrol the Device",
                           fill="black", font=('Helvetica 15 bold'))

        image = ImageTk.PhotoImage(qr_image)
        imagesprite = canvas.create_image(400, 300, image=image)
        canvas.pack()
        root.mainloop()
        q.put("Closed")

    @staticmethod
    def show_qr_screen_new_process(data: str, callback) -> QRMonitor:
        """Shows the QRCode in a new process and starts a QRMonitor
        for communicating with it

        Args:
            data (str): data to be shown in the QRCode
            callback (function): callback to be made when the window is closed

        Returns:
            QRMonitor: monitor used to receive callbacks and shutdown the window
        """
        q = Queue()
        p = Process(target=UI.show_qr_code, args=(q, data,))
        monitor = QRMonitor(q, p, callback)
        p.start()
        return monitor

#!usr/bin/env python3
from pyzbar import pyzbar
import cv2
import pyqrcode
from PIL import Image


def read_barcodes(frame):
    qr = pyzbar.decode(frame)
    QRText = ""
    for qr in qr:
        x, y, w, h = qr.rect
        QRText = QRText.replace("", qr.data.decode('utf-8'))
        print(QRText)
        cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
    return frame, QRText


def createUserQR(user):
    qr = pyqrcode.create(user)
    qr.png("userQR.png", scale=6)


def decodeUserQR(QRFile):
    data = pyzbar.decode(Image.open(QRFile))
    return data


def cameraReadQR():
    camera = cv2.VideoCapture(0)
    ret, frame = camera.read()
    while ret:
        ret, frame = camera.read()
        frame, text = read_barcodes(frame)
        cv2.imshow('Barcode reader', frame)
        # Get rid of text != "" to remove camera turning off after getting a QR code
        if (cv2.waitKey(1) == ord("q")) or text != "":
            break
    camera.release()
    cv2.destroyAllWindows()


def main():
    cameraReadQR()


if __name__ == '__main__':
    main()

################################################## 
# EchoService_services.py 
# generated by ZSI.generate.wsdl2python
##################################################


from EchoService_services_types import *
import urlparse, types
from ZSI.TCcompound import ComplexType, Struct
from ZSI import client
import ZSI
from ZSI.generate.pyclass import pyclass_type

# Locator
class EchoServiceLocator:
    Echo_address = "http://localhost:7100"
    def getEchoAddress(self):
        return EchoServiceLocator.Echo_address
    def getEcho(self, url=None, **kw):
        return EchoBindingSOAP(url or EchoServiceLocator.Echo_address, **kw)

# Methods
class EchoBindingSOAP:
    def __init__(self, url, **kw):
        kw.setdefault("readerclass", None)
        kw.setdefault("writerclass", None)
        # no resource properties
        self.binding = client.Binding(url=url, **kw)
        # no ws-addressing

    # op: <ZSI.wstools.WSDLTools.Message instance at 0x406f8b8c>
    def Echo(self, EchoIn):

        request = EchoInputMsg()
        request._EchoIn = EchoIn

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="Echo", **kw)
        # no output wsaction
        response = self.binding.Receive(EchoOutputMsg.typecode)
        EchoResult = response._EchoResult
        return EchoResult

EchoInputMsg = ns0.Echo_Dec().pyclass

EchoOutputMsg = ns0.EchoResponse_Dec().pyclass
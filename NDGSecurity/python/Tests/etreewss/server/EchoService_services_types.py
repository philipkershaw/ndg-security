################################################## 
# EchoService_services_types.py 
# generated by ZSI.generate.wsdl2python
##################################################


import ZSI
import ZSI.TCcompound
from ZSI.schema import LocalElementDeclaration, ElementDeclaration, TypeDefinition, GTD, GED
from ZSI.generate.pyclass import pyclass_type

##############################
# targetNamespace
# urn:ndg:security:test:wssecurity
##############################

class ns0:
    targetNamespace = "urn:ndg:security:test:wssecurity"

    class Echo_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "Echo"
        schema = "urn:ndg:security:test:wssecurity"
        def __init__(self, **kw):
            ns = ns0.Echo_Dec.schema
            TClist = [ZSI.TC.String(pname=(ns,"EchoIn"), aname="_EchoIn", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:ndg:security:test:wssecurity","Echo")
            kw["aname"] = "_Echo"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._EchoIn = None
                    return
            Holder.__name__ = "Echo_Holder"
            self.pyclass = Holder

    class EchoResponse_Dec(ZSI.TCcompound.ComplexType, ElementDeclaration):
        literal = "EchoResponse"
        schema = "urn:ndg:security:test:wssecurity"
        def __init__(self, **kw):
            ns = ns0.EchoResponse_Dec.schema
            TClist = [ZSI.TC.String(pname=(ns,"EchoResult"), aname="_EchoResult", minOccurs=0, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:ndg:security:test:wssecurity","EchoResponse")
            kw["aname"] = "_EchoResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self,None,TClist,inorder=0,**kw)
            class Holder:
                __metaclass__ = pyclass_type
                typecode = self
                def __init__(self):
                    # pyclass
                    self._EchoResult = None
                    return
            Holder.__name__ = "EchoResponse_Holder"
            self.pyclass = Holder

# end class ns0 (tns: urn:ndg:security:test:wssecurity)
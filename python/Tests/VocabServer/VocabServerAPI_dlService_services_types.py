################################################## 
# VocabServerAPI_dlService_services_types.py 
# generated by ZSI.generate.wsdl2python
##################################################


import ZSI
import ZSI.TCcompound
from ZSI.TC import ElementDeclaration,TypeDefinition
from ZSI.TC import _get_type_definition as GTD, _get_global_element_declaration as GED

##############################
# targetNamespace
# urn:VocabServerAPI_dl
##############################

class urn_VocabServerAPI_dl:
    targetNamespace = "urn:VocabServerAPI_dl"

    class whatLists(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "whatLists"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.whatLists.schema
            TClist = [ZSI.TC.String(pname=(ns,"in0"), aname="in0", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","whatLists")
            kw["aname"] = "whatLists"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.in0 = None
                    return
            Holder.__name__ = "whatLists_Holder"
            self.pyclass = Holder

    class whatListsResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "whatListsResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.whatListsResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"whatListsReturn"), aname="whatListsReturn", minOccurs=1, maxOccurs="unbounded", nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","whatListsResponse")
            kw["aname"] = "whatListsResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.whatListsReturn = []
                    return
            Holder.__name__ = "whatListsResponse_Holder"
            self.pyclass = Holder

    class getList(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "getList"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.getList.schema
            TClist = [ZSI.TC.String(pname=(ns,"in0"), aname="in0", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in1"), aname="in1", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in2"), aname="in2", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","getList")
            kw["aname"] = "getList"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.in0 = None
                    self.in1 = None
                    self.in2 = None
                    return
            Holder.__name__ = "getList_Holder"
            self.pyclass = Holder

    class getListResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "getListResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.getListResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"getListReturn"), aname="getListReturn", minOccurs=1, maxOccurs="unbounded", nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","getListResponse")
            kw["aname"] = "getListResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.getListReturn = []
                    return
            Holder.__name__ = "getListResponse_Holder"
            self.pyclass = Holder

    class verifyTerm(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "verifyTerm"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.verifyTerm.schema
            TClist = [ZSI.TC.String(pname=(ns,"in0"), aname="in0", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in1"), aname="in1", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in2"), aname="in2", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","verifyTerm")
            kw["aname"] = "verifyTerm"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.in0 = None
                    self.in1 = None
                    self.in2 = None
                    return
            Holder.__name__ = "verifyTerm_Holder"
            self.pyclass = Holder

    class verifyTermResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "verifyTermResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.verifyTermResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"verifyTermReturn"), aname="verifyTermReturn", minOccurs=1, maxOccurs="unbounded", nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","verifyTermResponse")
            kw["aname"] = "verifyTermResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.verifyTermReturn = []
                    return
            Holder.__name__ = "verifyTermResponse_Holder"
            self.pyclass = Holder

    class pvMap(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "pvMap"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.pvMap.schema
            TClist = [ZSI.TC.String(pname=(ns,"in0"), aname="in0", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in1"), aname="in1", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in2"), aname="in2", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","pvMap")
            kw["aname"] = "pvMap"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.in0 = None
                    self.in1 = None
                    self.in2 = None
                    return
            Holder.__name__ = "pvMap_Holder"
            self.pyclass = Holder

    class pvMapResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "pvMapResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.pvMapResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"pvMapReturn"), aname="pvMapReturn", minOccurs=1, maxOccurs="unbounded", nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","pvMapResponse")
            kw["aname"] = "pvMapResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.pvMapReturn = []
                    return
            Holder.__name__ = "pvMapResponse_Holder"
            self.pyclass = Holder

    class getPhenomDict(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "getPhenomDict"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.getPhenomDict.schema
            TClist = [ZSI.TC.String(pname=(ns,"in0"), aname="in0", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","getPhenomDict")
            kw["aname"] = "getPhenomDict"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.in0 = None
                    return
            Holder.__name__ = "getPhenomDict_Holder"
            self.pyclass = Holder

    class getPhenomDictResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "getPhenomDictResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.getPhenomDictResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"getPhenomDictReturn"), aname="getPhenomDictReturn", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","getPhenomDictResponse")
            kw["aname"] = "getPhenomDictResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.getPhenomDictReturn = None
                    return
            Holder.__name__ = "getPhenomDictResponse_Holder"
            self.pyclass = Holder

    class whatListsCat(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "whatListsCat"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.whatListsCat.schema
            TClist = []
            kw["pname"] = ("urn:VocabServerAPI_dl","whatListsCat")
            kw["aname"] = "whatListsCat"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    return
            Holder.__name__ = "whatListsCat_Holder"
            self.pyclass = Holder

    class whatListsCatResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "whatListsCatResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.whatListsCatResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"whatListsCatReturn"), aname="whatListsCatReturn", minOccurs=1, maxOccurs="unbounded", nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","whatListsCatResponse")
            kw["aname"] = "whatListsCatResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.whatListsCatReturn = []
                    return
            Holder.__name__ = "whatListsCatResponse_Holder"
            self.pyclass = Holder

    class searchVocab(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "searchVocab"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.searchVocab.schema
            TClist = [ZSI.TC.String(pname=(ns,"in0"), aname="in0", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in1"), aname="in1", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded")), ZSI.TC.String(pname=(ns,"in2"), aname="in2", minOccurs=1, maxOccurs=1, nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","searchVocab")
            kw["aname"] = "searchVocab"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.in0 = None
                    self.in1 = None
                    self.in2 = None
                    return
            Holder.__name__ = "searchVocab_Holder"
            self.pyclass = Holder

    class searchVocabResponse(ZSI.TCcompound.ComplexType, ElementDeclaration):
        schema = "urn:VocabServerAPI_dl"
        literal = "searchVocabResponse"
        def __init__(self, **kw):
            ns = urn_VocabServerAPI_dl.searchVocabResponse.schema
            TClist = [ZSI.TC.String(pname=(ns,"searchVocabReturn"), aname="searchVocabReturn", minOccurs=1, maxOccurs="unbounded", nillable=False, typed=False, encoded=kw.get("encoded"))]
            kw["pname"] = ("urn:VocabServerAPI_dl","searchVocabResponse")
            kw["aname"] = "searchVocabResponse"
            self.attribute_typecode_dict = {}
            ZSI.TCcompound.ComplexType.__init__(self, None, TClist, inorder=0, **kw)
            class Holder:
                typecode = self
                def __init__(self):
                    # pyclass
                    self.searchVocabReturn = []
                    return
            Holder.__name__ = "searchVocabResponse_Holder"
            self.pyclass = Holder

# end class urn_VocabServerAPI_dl (tns: urn:VocabServerAPI_dl)
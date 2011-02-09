from elementtree import ElementC14N as ET
from ZSI.wstools.Utility import ElementProxy as _ElementProxy

class ElementProxy(_ElementProxy):
    '''
    '''

    def __init__(self, sw, **kw):
        '''Initialize. 
           sw -- SoapWriter
        '''
        _ElementProxy.__init__(self, sw, **kw)

        self._dom = DOM
        self.node = None

    def __str__(self):
        return self.toString()

    def evaluate(self, expression, processorNss=None):
        '''expression -- XPath compiled expression
        '''
        nodes = elem.findall(expression, 
                             namespaces=processorNss or self.processorNss)

        return map(lambda node: ElementProxy(self.sw, node), nodes)

    #############################################
    # Methods for checking/setting the
    # classes (namespaceURI,name) node. 
    #############################################
    def checkNode(self, namespaceURI=None, localName=None):
        '''
            namespaceURI -- namespace of element
            localName -- local name of element
        '''
        namespaceURI = namespaceURI or self.namespaceURI
        localName = localName or self.name
        check = False
        if localName and self.node:
            check = self._dom.isElement(self.node, localName, namespaceURI)
        if not check:
            raise NamespaceError, 'unexpected node type %s, expecting %s' %(self.node, localName)

    def setNode(self, node=None):
        if node:
            if isinstance(node, ElementProxy):
                self.node = node._getNode()
            else:
                self.node = node
        elif self.node:
            node = self._dom.getElement(self.node, self.name, self.namespaceURI, default=None)
            if not node:
                raise NamespaceError, 'cant find element (%s,%s)' %(self.namespaceURI,self.name)
            self.node = node
        else:
            #self.node = self._dom.create(self.node, self.name, self.namespaceURI, default=None)
            self.createDocument(self.namespaceURI, localName=self.name, doctype=None)
        
        self.checkNode()

    #############################################
    # Wrapper Methods for direct DOM Element Node access
    #############################################
    def _getNode(self):
        return self.node

    def _getElements(self):
        return self._dom.getElements(self.node, name=None)

    def _getOwnerDocument(self):
        return self.node.ownerDocument or self.node

    def _getUniquePrefix(self):
        '''I guess we need to resolve all potential prefixes
        because when the current node is attached it copies the 
        namespaces into the parent node.
        '''
        while 1:
            self._indx += 1
            prefix = 'ns%d' %self._indx
            try:
                self._dom.findNamespaceURI(prefix, self._getNode())
            except DOMException, ex:
                break
        return prefix

    def _getPrefix(self, node, nsuri):
        '''
        Keyword arguments:
            node -- DOM Element Node
            nsuri -- namespace of attribute value
        '''
        try:
            if node and (node.nodeType == node.ELEMENT_NODE) and \
                (nsuri == self._dom.findDefaultNS(node)):
                return None
        except DOMException, ex:
            pass
        if nsuri == XMLNS.XML:
            return self._xml_prefix
        if node.nodeType == Node.ELEMENT_NODE:
            for attr in node.attributes.values():
                if attr.namespaceURI == XMLNS.BASE \
                   and nsuri == attr.value:
                        return attr.localName
            else:
                if node.parentNode:
                    return self._getPrefix(node.parentNode, nsuri)
        raise NamespaceError, 'namespaceURI "%s" is not defined' %nsuri

    def _appendChild(self, node):
        '''
        Keyword arguments:
            node -- DOM Element Node
        '''
        if node is None:
            raise TypeError, 'node is None'
        self.node.appendChild(node)

    def _insertBefore(self, newChild, refChild):
        '''
        Keyword arguments:
            child -- DOM Element Node to insert
            refChild -- DOM Element Node 
        '''
        self.node.insertBefore(newChild, refChild)

    def _setAttributeNS(self, namespaceURI, qualifiedName, value):
        '''
        Keyword arguments:
            namespaceURI -- namespace of attribute
            qualifiedName -- qualified name of new attribute value
            value -- value of attribute
        '''
        self.node.setAttributeNS(namespaceURI, qualifiedName, value)

    #############################################
    #General Methods
    #############################################
    def isFault(self):
        '''check to see if this is a soap:fault message.
        '''
        return False

    def getPrefix(self, namespaceURI):
        try:
            prefix = self._getPrefix(node=self.node, nsuri=namespaceURI)
        except NamespaceError, ex:
            prefix = self._getUniquePrefix() 
            self.setNamespaceAttribute(prefix, namespaceURI)
        return prefix

    def getDocument(self):
        return self._getOwnerDocument()

    def setDocument(self, document):
        self.node = document

    def importFromString(self, xmlString):
        doc = self._dom.loadDocument(StringIO(xmlString))
        node = self._dom.getElement(doc, name=None)
        clone = self.importNode(node)
        self._appendChild(clone)

    def importNode(self, node):
        if isinstance(node, ElementProxy):
            node = node._getNode()
        return self._dom.importNode(self._getOwnerDocument(), node, deep=1)

    def loadFromString(self, data):
        #self.node = self._dom.loadDocument(StringIO(data))
        self.node = ET.parse(StringIO(data))

    def canonicalize(self, **kw):
        f = StringIO()
        ETC14N.write(self.node, f, **kw)
        c14n = f.getvalue()
        return c14n

    def toString(self):
        return self.canonicalize()

    def createDocument(self, namespaceURI, localName, doctype=None):
        '''If specified must be a SOAP envelope, else may contruct an empty document.
        '''
        prefix = self._soap_env_prefix

        if namespaceURI == self.reserved_ns[prefix]:
            qualifiedName = '%s:%s' %(prefix,localName)
        elif namespaceURI is localName is None:
            self.node = self._dom.createDocument(None,None,None)
            return
        else:
            raise KeyError, 'only support creation of document in %s' %self.reserved_ns[prefix]

        document = self._dom.createDocument(nsuri=namespaceURI, qname=qualifiedName, doctype=doctype)
        self.node = document.childNodes[0]

        #set up reserved namespace attributes
        for prefix,nsuri in self.reserved_ns.items():
            self._setAttributeNS(namespaceURI=self._xmlns_nsuri, 
                qualifiedName='%s:%s' %(self._xmlns_prefix,prefix), 
                value=nsuri)

    #############################################
    #Methods for attributes
    #############################################
    def hasAttribute(self, namespaceURI, localName):
        return self._dom.hasAttr(self._getNode(), name=localName, nsuri=namespaceURI)

    def setAttributeType(self, namespaceURI, localName):
        '''set xsi:type
        Keyword arguments:
            namespaceURI -- namespace of attribute value
            localName -- name of new attribute value

        '''
        self.logger.debug('setAttributeType: (%s,%s)', namespaceURI, localName)
        value = localName
        if namespaceURI:
            value = '%s:%s' %(self.getPrefix(namespaceURI),localName)

        xsi_prefix = self.getPrefix(self._xsi_nsuri)
        self._setAttributeNS(self._xsi_nsuri, '%s:type' %xsi_prefix, value)

    def createAttributeNS(self, namespace, name, value):
        document = self._getOwnerDocument()
        attrNode = document.createAttributeNS(namespace, name, value)

    def setAttributeNS(self, namespaceURI, localName, value):
        '''
        Keyword arguments:
            namespaceURI -- namespace of attribute to create, None is for
                attributes in no namespace.
            localName -- local name of new attribute
            value -- value of new attribute
        ''' 
        prefix = None
        if namespaceURI:
            try:
                prefix = self.getPrefix(namespaceURI)
            except KeyError, ex:
                prefix = 'ns2'
                self.setNamespaceAttribute(prefix, namespaceURI)
        qualifiedName = localName
        if prefix:
            qualifiedName = '%s:%s' %(prefix, localName)
        self._setAttributeNS(namespaceURI, qualifiedName, value)

    def setNamespaceAttribute(self, prefix, namespaceURI):
        '''
        Keyword arguments:
            prefix -- xmlns prefix
            namespaceURI -- value of prefix
        '''
        self._setAttributeNS(XMLNS.BASE, 'xmlns:%s' %prefix, namespaceURI)

    #############################################
    #Methods for elements
    #############################################
    def createElementNS(self, namespace, qname):
        '''
        Keyword arguments:
            namespace -- namespace of element to create
            qname -- qualified name of new element
        '''
        document = self._getOwnerDocument()
        node = document.createElementNS(namespace, qname)
        return ElementProxy(self.sw, node)

    def createAppendSetElement(self, namespaceURI, localName, prefix=None):
        '''Create a new element (namespaceURI,name), append it
           to current node, then set it to be the current node.
        Keyword arguments:
            namespaceURI -- namespace of element to create
            localName -- local name of new element
            prefix -- if namespaceURI is not defined, declare prefix.  defaults
                to 'ns1' if left unspecified.
        '''
        node = self.createAppendElement(namespaceURI, localName, prefix=None)
        node=node._getNode()
        self._setNode(node._getNode())

    def createAppendElement(self, namespaceURI, localName, prefix=None):
        '''Create a new element (namespaceURI,name), append it
           to current node, and return the newly created node.
        Keyword arguments:
            namespaceURI -- namespace of element to create
            localName -- local name of new element
            prefix -- if namespaceURI is not defined, declare prefix.  defaults
                to 'ns1' if left unspecified.
        '''
        declare = False
        qualifiedName = localName
        if namespaceURI:
            try:
                prefix = self.getPrefix(namespaceURI)
            except:
                declare = True
                prefix = prefix or self._getUniquePrefix()
            if prefix: 
                qualifiedName = '%s:%s' %(prefix, localName)
        node = self.createElementNS(namespaceURI, qualifiedName)
        if declare:
            node._setAttributeNS(XMLNS.BASE, 'xmlns:%s' %prefix, namespaceURI)
        self._appendChild(node=node._getNode())
        return node

    def createInsertBefore(self, namespaceURI, localName, refChild):
        qualifiedName = localName
        prefix = self.getPrefix(namespaceURI)
        if prefix: 
            qualifiedName = '%s:%s' %(prefix, localName)
        node = self.createElementNS(namespaceURI, qualifiedName)
        self._insertBefore(newChild=node._getNode(), refChild=refChild._getNode())
        return node

    def getElement(self, namespaceURI, localName):
        '''
        Keyword arguments:
            namespaceURI -- namespace of element
            localName -- local name of element
        '''
        node = self._dom.getElement(self.node, localName, namespaceURI, default=None)
        if node:
            return ElementProxy(self.sw, node)
        return None

    def getAttributeValue(self, namespaceURI, localName):
        '''
        Keyword arguments:
            namespaceURI -- namespace of attribute
            localName -- local name of attribute
        '''
        if self.hasAttribute(namespaceURI, localName):
            attr = self.node.getAttributeNodeNS(namespaceURI,localName)
            return attr.value
        return None

    def getValue(self):
        return self._dom.getElementText(self.node, preserve_ws=True)    

    #############################################
    #Methods for text nodes
    #############################################
    def createAppendTextNode(self, pyobj):
        node = self.createTextNode(pyobj)
        self._appendChild(node=node._getNode())
        return node

    def createTextNode(self, pyobj):
        document = self._getOwnerDocument()
        node = document.createTextNode(pyobj)
        return ElementProxy(self.sw, node)

    #############################################
    #Methods for retrieving namespaceURI's
    #############################################
    def findNamespaceURI(self, qualifiedName):
        parts = SplitQName(qualifiedName)
        element = self._getNode()
        if len(parts) == 1:
            return (self._dom.findTargetNS(element), value)
        return self._dom.findNamespaceURI(parts[0], element)

    def resolvePrefix(self, prefix):
        element = self._getNode()
        return self._dom.findNamespaceURI(prefix, element)

    def getSOAPEnvURI(self):
        return self._soap_env_nsuri

    def isEmpty(self):
        return not self.node

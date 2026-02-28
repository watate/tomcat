/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.servlets;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.catalina.WebResource;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.util.DOMWriter;
import org.apache.catalina.util.XMLWriter;
import org.apache.tomcat.util.buf.HexUtils;
import org.apache.tomcat.util.http.ConcurrentDateFormat;
import org.apache.tomcat.util.http.FastHttpDateFormat;
import org.apache.tomcat.util.http.RequestUtil;
import org.apache.tomcat.util.security.ConcurrentMessageDigest;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Servlet which adds support for
 * <a href="https://tools.ietf.org/html/rfc4918">WebDAV</a>
 * <a href="https://tools.ietf.org/html/rfc4918#section-18">level 2</a>.
 * All the basic HTTP requests
 * are handled by the DefaultServlet. The WebDAVServlet must not be used as the
 * default servlet (ie mapped to '/') as it will not work in this configuration.
 * <p>
 * Mapping a subpath (e.g. <code>/webdav/*</code> to this servlet has the effect
 * of re-mounting the entire web application under that sub-path, with WebDAV
 * access to all the resources. The <code>WEB-INF</code> and <code>META-INF</code>
 * directories are protected in this re-mounted resource tree.
 * <p>
 * To enable WebDAV for a context add the following to web.xml:
 * <pre>
 * &lt;servlet&gt;
 *  &lt;servlet-name&gt;webdav&lt;/servlet-name&gt;
 *  &lt;servlet-class&gt;org.apache.catalina.servlets.WebdavServlet&lt;/servlet-class&gt;
 *    &lt;init-param&gt;
 *      &lt;param-name&gt;debug&lt;/param-name&gt;
 *      &lt;param-value&gt;0&lt;/param-value&gt;
 *    &lt;/init-param&gt;
 *    &lt;init-param&gt;
 *      &lt;param-name&gt;listings&lt;/param-name&gt;
 *      &lt;param-value&gt;false&lt;/param-value&gt;
 *    &lt;/init-param&gt;
 *  &lt;/servlet&gt;
 *  &lt;servlet-mapping&gt;
 *    &lt;servlet-name&gt;webdav&lt;/servlet-name&gt;
 *    &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 *  &lt;/servlet-mapping&gt;
 * </pre>
 * This will enable read only access. To enable read-write access add:
 * <pre>
 *  &lt;init-param&gt;
 *    &lt;param-name&gt;readonly&lt;/param-name&gt;
 *    &lt;param-value&gt;false&lt;/param-value&gt;
 *  &lt;/init-param&gt;
 * </pre>
 * To make the content editable via a different URL, use the following
 * mapping:
 * <pre>
 *  &lt;servlet-mapping&gt;
 *    &lt;servlet-name&gt;webdav&lt;/servlet-name&gt;
 *    &lt;url-pattern&gt;/webdavedit/*&lt;/url-pattern&gt;
 *  &lt;/servlet-mapping&gt;
 * </pre>
 * By default access to /WEB-INF and META-INF are not available via WebDAV. To
 * enable access to these URLs, use add:
 * <pre>
 *  &lt;init-param&gt;
 *    &lt;param-name&gt;allowSpecialPaths&lt;/param-name&gt;
 *    &lt;param-value&gt;true&lt;/param-value&gt;
 *  &lt;/init-param&gt;
 * </pre>
 * Don't forget to secure access appropriately to the editing URLs, especially
 * if allowSpecialPaths is used. With the mapping configuration above, the
 * context will be accessible to normal users as before. Those users with the
 * necessary access will be able to edit content available via
 * http://host:port/context/content using
 * http://host:port/context/webdavedit/content
 *
 * @author Remy Maucherat
 *
 * @see <a href="https://tools.ietf.org/html/rfc4918">RFC 4918</a>
 */
public class WebdavServlet extends DefaultServlet {

    private static final long serialVersionUID = 1L;


    // -------------------------------------------------------------- Constants

    private static final String METHOD_PROPFIND = "PROPFIND";
    private static final String METHOD_PROPPATCH = "PROPPATCH";
    private static final String METHOD_MKCOL = "MKCOL";
    private static final String METHOD_COPY = "COPY";
    private static final String METHOD_MOVE = "MOVE";
    private static final String METHOD_LOCK = "LOCK";
    private static final String METHOD_UNLOCK = "UNLOCK";


    /**
     * PROPFIND - Specify a property mask.
     */
    private static final int FIND_BY_PROPERTY = 0;


    /**
     * PROPFIND - Display all properties.
     */
    private static final int FIND_ALL_PROP = 1;


    /**
     * PROPFIND - Return property names.
     */
    private static final int FIND_PROPERTY_NAMES = 2;


    /**
     * Create a new lock.
     */
    private static final int LOCK_CREATION = 0;


    /**
     * Refresh lock.
     */
    private static final int LOCK_REFRESH = 1;


    /**
     * Default lock timeout value.
     */
    private static final int DEFAULT_TIMEOUT = 3600;


    /**
     * Maximum lock timeout.
     */
    private static final int MAX_TIMEOUT = 604800;


    /**
     * Default namespace.
     */
    protected static final String DEFAULT_NAMESPACE = "DAV:";


    /**
     * Simple date format for the creation date ISO representation (partial).
     */
    protected static final ConcurrentDateFormat creationDateFormat = new ConcurrentDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US, TimeZone.getTimeZone("GMT"));


    // ----------------------------------------------------- Instance Variables

    /**
     * Repository of the locks put on single resources.
     * <p>
     * Key : path <br>
     * Value : LockInfo
     */
    private final Map<String,LockInfo> resourceLocks = new ConcurrentHashMap<>();


    /**
     * Repository of the lock-null resources.
     * <p>
     * Key : path of the collection containing the lock-null resource<br>
     * Value : List of lock-null resource which are members of the
     * collection. Each element of the List is the path associated with
     * the lock-null resource.
     */
    private final Map<String,List<String>> lockNullResources = new ConcurrentHashMap<>();


    /**
     * List of the inheritable collection locks.
     */
    private final List<LockInfo> collectionLocks = Collections.synchronizedList(new ArrayList<>());


    /**
     * Secret information used to generate reasonably secure lock ids.
     */
    private String secret = "catalina";


    /**
     * Default depth in spec is infinite. Limit depth to 3 by default as
     * infinite depth makes operations very expensive.
     */
    private int maxDepth = 3;


    /**
     * Is access allowed via WebDAV to the special paths (/WEB-INF and
     * /META-INF)?
     */
    private boolean allowSpecialPaths = false;


    // --------------------------------------------------------- Public Methods

    /**
     * Initialize this servlet.
     */
    @Override
    public void init() throws ServletException {

        super.init();

        if (getServletConfig().getInitParameter("secret") != null) {
            secret = getServletConfig().getInitParameter("secret");
        }

        if (getServletConfig().getInitParameter("maxDepth") != null) {
            maxDepth = Integer.parseInt(
                    getServletConfig().getInitParameter("maxDepth"));
        }

        if (getServletConfig().getInitParameter("allowSpecialPaths") != null) {
            allowSpecialPaths = Boolean.parseBoolean(
                    getServletConfig().getInitParameter("allowSpecialPaths"));
        }
    }


    // ------------------------------------------------------ Protected Methods

    /**
     * Return JAXP document builder instance.
     * @return the document builder
     * @throws ServletException document builder creation failed
     *  (wrapped <code>ParserConfigurationException</code> exception)
     */
    protected DocumentBuilder getDocumentBuilder() throws ServletException {
        DocumentBuilder documentBuilder = null;
        DocumentBuilderFactory documentBuilderFactory = null;
        try {
            documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            documentBuilderFactory.setExpandEntityReferences(false);
            documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            documentBuilderFactory.setXIncludeAware(false);
            documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
            documentBuilder.setEntityResolver(new WebdavResolver(this.getServletContext()));
        } catch(ParserConfigurationException | IllegalArgumentException e) {
            throw new ServletException(sm.getString("webdavservlet.jaxpfailed"));
        }
        return documentBuilder;
    }

    /**
     * Handles the special WebDAV methods.
     */
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        final String path = getRelativePath(req);

        if (req.getDispatcherType() == DispatcherType.ERROR) {
            doGet(req, resp);
            return;
        }

        if (isSpecialPath(path)) {
            resp.sendError(WebdavStatus.SC_NOT_FOUND);
            return;
        }

        final String method = req.getMethod();

        if (debug > 0) {
            log("[" + method + "] " + path);
        }

        if (method.equals(METHOD_PROPFIND)) {
            doPropfind(req, resp);
        } else if (method.equals(METHOD_PROPPATCH)) {
            doProppatch(req, resp);
        } else if (method.equals(METHOD_MKCOL)) {
            doMkcol(req, resp);
        } else if (method.equals(METHOD_COPY)) {
            doCopy(req, resp);
        } else if (method.equals(METHOD_MOVE)) {
            doMove(req, resp);
        } else if (method.equals(METHOD_LOCK)) {
            doLock(req, resp);
        } else if (method.equals(METHOD_UNLOCK)) {
            doUnlock(req, resp);
        } else {
            super.service(req, resp);
        }
    }

    private boolean isSpecialPath(final String path) {
        return !allowSpecialPaths && (
                path.toUpperCase(Locale.ENGLISH).startsWith("/WEB-INF") ||
                path.toUpperCase(Locale.ENGLISH).startsWith("/META-INF"));
    }

    @Override
    protected boolean checkIfHeaders(HttpServletRequest request, HttpServletResponse response, WebResource resource)
            throws IOException {

        if (!super.checkIfHeaders(request, response, resource)) {
            return false;
        }

        return true;
    }

    @Override
    protected String getRelativePath(HttpServletRequest request) {
        return getRelativePath(request, false);
    }

    @Override
    protected String getRelativePath(HttpServletRequest request, boolean allowEmptyPath) {
        String pathInfo;

        if (request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null) {
            pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
        } else {
            pathInfo = request.getPathInfo();
        }

        StringBuilder result = new StringBuilder();
        if (pathInfo != null) {
            result.append(pathInfo);
        }
        if (result.length() == 0) {
            result.append('/');
        }

        return result.toString();
    }

    @Override
    protected String getPathPrefix(final HttpServletRequest request) {
        String contextPath = request.getContextPath();
        if (request.getServletPath() !=  null) {
            contextPath = contextPath + request.getServletPath();
        }
        return contextPath;
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.addHeader("DAV", "1,2");
        resp.addHeader("Allow", determineMethodsAllowed(req));
        resp.addHeader("MS-Author-Via", "DAV");
    }

    protected void doPropfind(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        if (!listings) {
            sendNotAllowed(req, resp);
            return;
        }

        String path = getRelativePath(req);
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }

        List<String> properties = null;
        int depth = maxDepth;
        int type = FIND_ALL_PROP;

        String depthStr = req.getHeader("Depth");

        if (depthStr == null) {
            depth = maxDepth;
        } else {
            if (depthStr.equals("0")) {
                depth = 0;
            } else if (depthStr.equals("1")) {
                depth = 1;
            } else if (depthStr.equals("infinity")) {
                depth = maxDepth;
            }
        }

        Node propNode = null;

        if (req.getContentLengthLong() > 0) {
            DocumentBuilder documentBuilder = getDocumentBuilder();

            try {
                Document document = documentBuilder.parse(new InputSource(req.getInputStream()));

                Element rootElement = document.getDocumentElement();
                NodeList childList = rootElement.getChildNodes();

                for (int i=0; i < childList.getLength(); i++) {
                    Node currentNode = childList.item(i);
                    switch (currentNode.getNodeType()) {
                    case Node.TEXT_NODE:
                        break;
                    case Node.ELEMENT_NODE:
                        if (currentNode.getNodeName().endsWith("prop")) {
                            type = FIND_BY_PROPERTY;
                            propNode = currentNode;
                        }
                        if (currentNode.getNodeName().endsWith("propname")) {
                            type = FIND_PROPERTY_NAMES;
                        }
                        if (currentNode.getNodeName().endsWith("allprop")) {
                            type = FIND_ALL_PROP;
                        }
                        break;
                    }
                }
            } catch (SAXException | IOException e) {
                resp.sendError(WebdavStatus.SC_BAD_REQUEST);
                return;
            }
        }

        if (type == FIND_BY_PROPERTY) {
            properties = new ArrayList<>();
            @SuppressWarnings("null")
            NodeList childList = propNode.getChildNodes();

            for (int i=0; i < childList.getLength(); i++) {
                Node currentNode = childList.item(i);
                switch (currentNode.getNodeType()) {
                case Node.TEXT_NODE:
                    break;
                case Node.ELEMENT_NODE:
                    String nodeName = currentNode.getNodeName();
                    String propertyName = null;
                    if (nodeName.indexOf(':') != -1) {
                        propertyName = nodeName.substring
                            (nodeName.indexOf(':') + 1);
                    } else {
                        propertyName = nodeName;
                    }
                    properties.add(propertyName);
                    break;
                }
            }
        }

        WebResource resource = resources.getResource(path);

        if (!resource.exists()) {
            int slash = path.lastIndexOf('/');
            if (slash != -1) {
                String parentPath = path.substring(0, slash);
                List<String> currentLockNullResources = lockNullResources.get(parentPath);
                if (currentLockNullResources != null) {
                    for (String lockNullPath : currentLockNullResources) {
                        if (lockNullPath.equals(path)) {
                            resp.setStatus(WebdavStatus.SC_MULTI_STATUS);
                            resp.setContentType("text/xml; charset=UTF-8");
                            XMLWriter generatedXML = new XMLWriter(resp.getWriter());
                            generatedXML.writeXMLHeader();
                            generatedXML.writeElement("D", DEFAULT_NAMESPACE, "multistatus", XMLWriter.OPENING);
                            parseLockNullProperties(req, generatedXML, lockNullPath, type, properties);
                            generatedXML.writeElement("D", "multistatus", XMLWriter.CLOSING);
                            generatedXML.sendData();
                            return;
                        }
                    }
                }
            }
        }

        if (!resource.exists()) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        resp.setStatus(WebdavStatus.SC_MULTI_STATUS);

        resp.setContentType("text/xml; charset=UTF-8");

        XMLWriter generatedXML = new XMLWriter(resp.getWriter());
        generatedXML.writeXMLHeader();

        generatedXML.writeElement("D", DEFAULT_NAMESPACE, "multistatus", XMLWriter.OPENING);

        if (depth == 0) {
            parseProperties(req, generatedXML, path, type, properties);
        } else {
            Deque<String> stack = new ArrayDeque<>();
            stack.addFirst(path);

            Deque<String> stackBelow = new ArrayDeque<>();

            while ((!stack.isEmpty()) && (depth >= 0)) {

                String currentPath = stack.remove();
                parseProperties(req, generatedXML, currentPath, type, properties);

                resource = resources.getResource(currentPath);

                if (resource.isDirectory() && (depth > 0)) {

                    String[] entries = resources.list(currentPath);
                    for (String entry : entries) {
                        String newPath = currentPath;
                        if (!(newPath.endsWith("/"))) {
                            newPath += "/";
                        }
                        newPath += entry;
                        stackBelow.addFirst(newPath);
                    }

                    String lockPath = currentPath;
                    if (lockPath.endsWith("/")) {
                        lockPath = lockPath.substring(0, lockPath.length() - 1);
                    }
                    List<String> currentLockNullResources = lockNullResources.get(lockPath);
                    if (currentLockNullResources != null) {
                        for (String lockNullPath : currentLockNullResources) {
                            parseLockNullProperties(req, generatedXML, lockNullPath, type, properties);
                        }
                    }
                }

                if (stack.isEmpty()) {
                    depth--;
                    stack = stackBelow;
                    stackBelow = new ArrayDeque<>();
                }

                generatedXML.sendData();

            }
        }

        generatedXML.writeElement("D", "multistatus", XMLWriter.CLOSING);

        generatedXML.sendData();

    }

    protected void doProppatch(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        if (readOnly) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return;
        }

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        resp.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED);
    }

    protected void doMkcol(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String path = getRelativePath(req);

        WebResource resource = resources.getResource(path);

        if (resource.exists()) {
            sendNotAllowed(req, resp);
            return;
        }

        if (readOnly) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return;
        }

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        if (req.getContentLengthLong() > 0) {
            DocumentBuilder documentBuilder = getDocumentBuilder();
            try {
                documentBuilder.parse(new InputSource(req.getInputStream()));
                resp.sendError(WebdavStatus.SC_NOT_IMPLEMENTED);
                return;

            } catch(SAXException saxe) {
                resp.sendError(WebdavStatus.SC_UNSUPPORTED_MEDIA_TYPE);
                return;
            }
        }

        if (resources.mkdir(path)) {
            resp.setStatus(WebdavStatus.SC_CREATED);
            lockNullResources.remove(path);
        } else {
            resp.sendError(WebdavStatus.SC_CONFLICT);
        }
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        if (readOnly) {
            sendNotAllowed(req, resp);
            return;
        }

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        deleteResource(req, resp);
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        String path = getRelativePath(req);
        WebResource resource = resources.getResource(path);
        if (resource.isDirectory()) {
            sendNotAllowed(req, resp);
            return;
        }

        super.doPut(req, resp);

        lockNullResources.remove(path);
    }

    protected void doCopy(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        if (readOnly) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return;
        }

        copyResource(req, resp);
    }

    protected void doMove(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        if (readOnly) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return;
        }

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        String path = getRelativePath(req);

        if (copyResource(req, resp)) {
            deleteResource(path, req, resp, false);
        }
    }

    protected void doLock(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        if (readOnly) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return;
        }

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        LockInfo lock = new LockInfo(maxDepth);

        String depthStr = req.getHeader("Depth");

        if (depthStr == null) {
            lock.depth = maxDepth;
        } else {
            if (depthStr.equals("0")) {
                lock.depth = 0;
            } else {
                lock.depth = maxDepth;
            }
        }

        int lockDuration = DEFAULT_TIMEOUT;
        String lockDurationStr = req.getHeader("Timeout");
        if (lockDurationStr != null) {
            int commaPos = lockDurationStr.indexOf(',');
            if (commaPos != -1) {
                lockDurationStr = lockDurationStr.substring(0,commaPos);
            }
            if (lockDurationStr.startsWith("Second-")) {
                lockDuration = Integer.parseInt(lockDurationStr.substring(7));
            } else {
                if (lockDurationStr.equalsIgnoreCase("infinity")) {
                    lockDuration = MAX_TIMEOUT;
                } else {
                    try {
                        lockDuration = Integer.parseInt(lockDurationStr);
                    } catch (NumberFormatException e) {
                        lockDuration = MAX_TIMEOUT;
                    }
                }
            }
            if (lockDuration == 0) {
                lockDuration = DEFAULT_TIMEOUT;
            }
            if (lockDuration > MAX_TIMEOUT) {
                lockDuration = MAX_TIMEOUT;
            }
        }
        lock.expiresAt = System.currentTimeMillis() + (lockDuration * 1000);

        int lockRequestType = LOCK_CREATION;

        Node lockInfoNode = null;

        DocumentBuilder documentBuilder = getDocumentBuilder();

        try {
            Document document = documentBuilder.parse(new InputSource(req.getInputStream()));

            Element rootElement = document.getDocumentElement();
            lockInfoNode = rootElement;
        } catch (IOException | SAXException e) {
            lockRequestType = LOCK_REFRESH;
        }

        if (lockInfoNode != null) {

            NodeList childList = lockInfoNode.getChildNodes();
            StringWriter strWriter = null;
            DOMWriter domWriter = null;

            Node lockScopeNode = null;
            Node lockTypeNode = null;
            Node lockOwnerNode = null;

            for (int i=0; i < childList.getLength(); i++) {
                Node currentNode = childList.item(i);
                switch (currentNode.getNodeType()) {
                case Node.TEXT_NODE:
                    break;
                case Node.ELEMENT_NODE:
                    String nodeName = currentNode.getNodeName();
                    if (nodeName.endsWith("lockscope")) {
                        lockScopeNode = currentNode;
                    }
                    if (nodeName.endsWith("locktype")) {
                        lockTypeNode = currentNode;
                    }
                    if (nodeName.endsWith("owner")) {
                        lockOwnerNode = currentNode;
                    }
                    break;
                }
            }

            if (lockScopeNode != null) {

                childList = lockScopeNode.getChildNodes();
                for (int i=0; i < childList.getLength(); i++) {
                    Node currentNode = childList.item(i);
                    switch (currentNode.getNodeType()) {
                    case Node.TEXT_NODE:
                        break;
                    case Node.ELEMENT_NODE:
                        String tempScope = currentNode.getNodeName();
                        if (tempScope.indexOf(':') != -1) {
                            lock.scope = tempScope.substring(tempScope.indexOf(':') + 1);
                        } else {
                            lock.scope = tempScope;
                        }
                        break;
                    }
                }

                if (lock.scope == null) {
                    resp.setStatus(WebdavStatus.SC_BAD_REQUEST);
                }

            } else {
                resp.setStatus(WebdavStatus.SC_BAD_REQUEST);
            }

            if (lockTypeNode != null) {

                childList = lockTypeNode.getChildNodes();
                for (int i=0; i < childList.getLength(); i++) {
                    Node currentNode = childList.item(i);
                    switch (currentNode.getNodeType()) {
                    case Node.TEXT_NODE:
                        break;
                    case Node.ELEMENT_NODE:
                        String tempType = currentNode.getNodeName();
                        if (tempType.indexOf(':') != -1) {
                            lock.type = tempType.substring(tempType.indexOf(':') + 1);
                        } else {
                            lock.type = tempType;
                        }
                        break;
                    }
                }

                if (lock.type == null) {
                    resp.setStatus(WebdavStatus.SC_BAD_REQUEST);
                }

            } else {
                resp.setStatus(WebdavStatus.SC_BAD_REQUEST);
            }

            if (lockOwnerNode != null) {

                childList = lockOwnerNode.getChildNodes();
                for (int i=0; i < childList.getLength(); i++) {
                    Node currentNode = childList.item(i);
                    switch (currentNode.getNodeType()) {
                    case Node.TEXT_NODE:
                        lock.owner += currentNode.getNodeValue();
                        break;
                    case Node.ELEMENT_NODE:
                        strWriter = new StringWriter();
                        domWriter = new DOMWriter(strWriter);
                        domWriter.print(currentNode);
                        lock.owner += strWriter.toString();
                        break;
                    }
                }

                if (lock.owner == null) {
                    resp.setStatus(WebdavStatus.SC_BAD_REQUEST);
                }

            } else {
                lock.owner = "";
            }
        }

        String path = getRelativePath(req);

        lock.path = path;

        WebResource resource = resources.getResource(path);

        if (lockRequestType == LOCK_CREATION) {

            String lockTokenStr = req.getServletPath() + "-" + lock.type + "-" +
                    lock.scope + "-" + req.getUserPrincipal() + "-" +
                    lock.depth + "-" + lock.owner + "-" + lock.tokens + "-" +
                    lock.expiresAt + "-" + System.currentTimeMillis() + "-" +
                    secret;
            String lockToken = HexUtils.toHexString(ConcurrentMessageDigest.digestMD5(
                    lockTokenStr.getBytes(StandardCharsets.ISO_8859_1)));

            if (resource.isDirectory() && lock.depth == maxDepth) {

                List<String> lockPaths = new ArrayList<>();
                for (LockInfo currentLock : collectionLocks) {
                    if (currentLock.hasExpired()) {
                        collectionLocks.remove(currentLock);
                        continue;
                    }
                    if (currentLock.path.startsWith(lock.path) &&
                            (currentLock.isExclusive() || lock.isExclusive())) {
                        lockPaths.add(currentLock.path);
                    }
                }
                for (LockInfo currentLock : resourceLocks.values()) {
                    if (currentLock.hasExpired()) {
                        resourceLocks.remove(currentLock.path);
                        continue;
                    }
                    if (currentLock.path.startsWith(lock.path) &&
                            (currentLock.isExclusive() || lock.isExclusive())) {
                        lockPaths.add(currentLock.path);
                    }
                }

                if (!lockPaths.isEmpty()) {

                    resp.setStatus(WebdavStatus.SC_CONFLICT);

                    XMLWriter generatedXML = new XMLWriter();
                    generatedXML.writeXMLHeader();

                    generatedXML.writeElement("D", DEFAULT_NAMESPACE, "multistatus", XMLWriter.OPENING);

                    for (String lockPath : lockPaths) {
                        generatedXML.writeElement("D", "response", XMLWriter.OPENING);
                        generatedXML.writeElement("D", "href", XMLWriter.OPENING);
                        generatedXML.writeText(lockPath);
                        generatedXML.writeElement("D", "href", XMLWriter.CLOSING);
                        generatedXML.writeElement("D", "status", XMLWriter.OPENING);
                        generatedXML.writeText("HTTP/1.1 " + WebdavStatus.SC_LOCKED + " ");
                        generatedXML.writeElement("D", "status", XMLWriter.CLOSING);
                        generatedXML.writeElement("D", "response", XMLWriter.CLOSING);
                    }

                    generatedXML.writeElement("D", "multistatus", XMLWriter.CLOSING);

                    Writer writer = resp.getWriter();
                    writer.write(generatedXML.toString());
                    writer.close();

                    return;
                }

                boolean addLock = true;

                for (LockInfo currentLock : collectionLocks) {
                    if (currentLock.path.equals(lock.path)) {

                        if (currentLock.isExclusive()) {
                            resp.sendError(WebdavStatus.SC_LOCKED);
                            return;
                        } else {
                            if (lock.isExclusive()) {
                                resp.sendError(WebdavStatus.SC_LOCKED);
                                return;
                            }
                        }

                        currentLock.tokens.add(lockToken);
                        lock = currentLock;
                        addLock = false;
                    }
                }

                if (addLock) {
                    lock.tokens.add(lockToken);
                    collectionLocks.add(lock);
                }

            } else {

                LockInfo presentLock = resourceLocks.get(lock.path);
                if (presentLock != null) {

                    if ((presentLock.isExclusive()) || (lock.isExclusive())) {
                        resp.sendError(WebdavStatus.SC_PRECONDITION_FAILED);
                        return;
                    } else {
                        presentLock.tokens.add(lockToken);
                        lock = presentLock;
                    }

                } else {

                    lock.tokens.add(lockToken);
                    resourceLocks.put(lock.path, lock);

                    if (!resource.exists()) {

                        int slash = lock.path.lastIndexOf('/');
                        String parentPath = lock.path.substring(0, slash);

                        lockNullResources.computeIfAbsent(parentPath, k -> new ArrayList<>()).add(lock.path);
                    }

                    resp.addHeader("Lock-Token", "<opaquelocktoken:" + lockToken + ">");
                }
            }
        }

        if (lockRequestType == LOCK_REFRESH) {

            String ifHeader = req.getHeader("If");
            if (ifHeader == null) {
                ifHeader = "";
            }

            LockInfo toRenew = resourceLocks.get(path);

            if (toRenew != null) {
                for (String token : toRenew.tokens) {
                    if (ifHeader.contains(token)) {
                        toRenew.expiresAt = lock.expiresAt;
                        lock = toRenew;
                    }
                }
            }

            for (LockInfo collecionLock : collectionLocks) {
                if (path.equals(collecionLock.path)) {
                    for (String token : collecionLock.tokens) {
                        if (ifHeader.contains(token)) {
                            collecionLock.expiresAt = lock.expiresAt;
                            lock = collecionLock;
                        }
                    }
                }
            }
        }

        XMLWriter generatedXML = new XMLWriter();
        generatedXML.writeXMLHeader();
        generatedXML.writeElement("D", DEFAULT_NAMESPACE, "prop", XMLWriter.OPENING);

        generatedXML.writeElement("D", "lockdiscovery", XMLWriter.OPENING);

        lock.toXML(generatedXML);

        generatedXML.writeElement("D", "lockdiscovery", XMLWriter.CLOSING);

        generatedXML.writeElement("D", "prop", XMLWriter.CLOSING);

        resp.setStatus(WebdavStatus.SC_OK);
        resp.setContentType("text/xml; charset=UTF-8");
        Writer writer = resp.getWriter();
        writer.write(generatedXML.toString());
        writer.close();
    }

    protected void doUnlock(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        if (readOnly) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return;
        }

        if (isLocked(req)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return;
        }

        String path = getRelativePath(req);

        String lockTokenHeader = req.getHeader("Lock-Token");
        if (lockTokenHeader == null) {
            lockTokenHeader = "";
        }

        LockInfo lock = resourceLocks.get(path);
        if (lock != null) {

            Iterator<String> tokenList = lock.tokens.iterator();
            while (tokenList.hasNext()) {
                String token = tokenList.next();
                if (lockTokenHeader.contains(token)) {
                    tokenList.remove();
                }
            }

            if (lock.tokens.isEmpty()) {
                resourceLocks.remove(path);
                lockNullResources.remove(path);
            }

        }

        Iterator<LockInfo> collectionLocksList = collectionLocks.iterator();
        while (collectionLocksList.hasNext()) {
            lock = collectionLocksList.next();
            if (path.equals(lock.path)) {
                Iterator<String> tokenList = lock.tokens.iterator();
                while (tokenList.hasNext()) {
                    String token = tokenList.next();
                    if (lockTokenHeader.contains(token)) {
                        tokenList.remove();
                        break;
                    }
                }
                if (lock.tokens.isEmpty()) {
                    collectionLocksList.remove();
                    lockNullResources.remove(path);
                }
            }
        }

        resp.setStatus(WebdavStatus.SC_NO_CONTENT);
    }

    private boolean isLocked(HttpServletRequest req) {

        String path = getRelativePath(req);

        String ifHeader = req.getHeader("If");
        if (ifHeader == null) {
            ifHeader = "";
        }

        String lockTokenHeader = req.getHeader("Lock-Token");
        if (lockTokenHeader == null) {
            lockTokenHeader = "";
        }

        return isLocked(path, ifHeader + lockTokenHeader);
    }

    private boolean isLocked(String path, String ifHeader) {

        LockInfo lock = resourceLocks.get(path);
        if ((lock != null) && (lock.hasExpired())) {
            resourceLocks.remove(path);
        } else if (lock != null) {

            boolean tokenMatch = false;
            for (String token : lock.tokens) {
                if (ifHeader.contains(token)) {
                    tokenMatch = true;
                    break;
                }
            }
            if (!tokenMatch) {
                return true;
            }
        }

        Iterator<LockInfo> collectionLockList = collectionLocks.iterator();
        while (collectionLockList.hasNext()) {
            lock = collectionLockList.next();
            if (lock.hasExpired()) {
                collectionLockList.remove();
            } else if (path.startsWith(lock.path)) {
                boolean tokenMatch = false;
                for (String token : lock.tokens) {
                    if (ifHeader.contains(token)) {
                        tokenMatch = true;
                        break;
                    }
                }
                if (!tokenMatch) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean copyResource(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        String path = getRelativePath(req);
        WebResource source = resources.getResource(path);
        if (!source.exists()) {
            resp.sendError(WebdavStatus.SC_NOT_FOUND);
            return false;
        }

        String destinationHeader = req.getHeader("Destination");

        if (destinationHeader == null  || destinationHeader.isEmpty()) {
            resp.sendError(WebdavStatus.SC_BAD_REQUEST);
            return false;
        }

        URI destinationUri;
        try {
            destinationUri = new URI (destinationHeader);
        } catch (URISyntaxException e) {
            resp.sendError(WebdavStatus.SC_BAD_REQUEST);
            return false;
        }

        String destinationPath = destinationUri.getPath();

        if (!destinationPath.equals(RequestUtil.normalize(destinationPath))) {
            resp.sendError(WebdavStatus.SC_BAD_REQUEST);
            return false;
        }

        if (destinationUri.isAbsolute()) {
            if (!req.getScheme().equals(destinationUri.getScheme()) ||
                    !req.getServerName().equals(destinationUri.getHost())) {
                resp.sendError(WebdavStatus.SC_FORBIDDEN);
                return false;
            }
            if (req.getServerPort() != destinationUri.getPort()) {
                if (destinationUri.getPort() == -1 &&
                        ("http".equals(req.getScheme()) && req.getServerPort() == 80 ||
                        "https".equals(req.getScheme()) && req.getServerPort() == 443)) {
                } else {
                    resp.sendError(WebdavStatus.SC_FORBIDDEN);
                    return false;
                }
            }
        }

        String reqContextPath = req.getContextPath();
        if (!destinationPath.startsWith(reqContextPath + "/")) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return false;
        }

        destinationPath = destinationPath.substring(reqContextPath.length() + req.getServletPath().length());

        if (debug > 0) {
            log("Dest path :" + destinationPath);
        }

        if (isSpecialPath(destinationPath)) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return false;
        }

        if (destinationPath.equals(path)) {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return false;
        }

        if (destinationPath.startsWith(path) && destinationPath.charAt(path.length()) == '/' ||
                path.startsWith(destinationPath) && path.charAt(destinationPath.length()) == '/') {
            resp.sendError(WebdavStatus.SC_FORBIDDEN);
            return false;
        }

        boolean overwrite = true;
        String overwriteHeader = req.getHeader("Overwrite");
        if (overwriteHeader != null) {
            if (overwriteHeader.equalsIgnoreCase("T")) {
                overwrite = true;
            } else {
                overwrite = false;
            }
        }

        WebResource destination = resources.getResource(destinationPath);
        if (overwrite) {
            if (destination.exists()) {
                if (!deleteResource(destinationPath, req, resp, true)) {
                    return false;
                }
            } else {
                resp.setStatus(WebdavStatus.SC_CREATED);
            }
        } else {
            if (destination.exists()) {
                resp.sendError(WebdavStatus.SC_PRECONDITION_FAILED);
                return false;
            }
        }

        Map<String,Integer> errorList = new HashMap<>();

        boolean result = copyResource(errorList, path, destinationPath);

        if ((!result) || (!errorList.isEmpty())) {
            if (errorList.size() == 1) {
                resp.sendError(errorList.values().iterator().next().intValue());
            } else {
                sendReport(req, resp, errorList);
            }
            return false;
        }

        if (destination.exists()) {
            resp.setStatus(WebdavStatus.SC_NO_CONTENT);
        } else {
            resp.setStatus(WebdavStatus.SC_CREATED);
        }

        lockNullResources.remove(destinationPath);

        return true;
    }

    private boolean copyResource(Map<String,Integer> errorList, String source, String dest) {

        if (debug > 1) {
            log("Copy: " + source + " To: " + dest);
        }

        WebResource sourceResource = resources.getResource(source);

        if (sourceResource.isDirectory()) {
            if (!resources.mkdir(dest)) {
                WebResource destResource = resources.getResource(dest);
                if (!destResource.isDirectory()) {
                    errorList.put(dest, Integer.valueOf(WebdavStatus.SC_CONFLICT));
                    return false;
                }
            }

            String[] entries = resources.list(source);
            for (String entry : entries) {
                String childDest = dest;
                if (!childDest.equals("/")) {
                    childDest += "/";
                }
                childDest += entry;
                String childSrc = source;
                if (!childSrc.equals("/")) {
                    childSrc += "/";
                }
                childSrc += entry;
                copyResource(errorList, childSrc, childDest);
            }
        } else if (sourceResource.isFile()) {
            WebResource destResource = resources.getResource(dest);
            if (!destResource.exists() && !destResource.getWebappPath().endsWith("/")) {
                int lastSlash = destResource.getWebappPath().lastIndexOf('/');
                if (lastSlash > 0) {
                    String parent = destResource.getWebappPath().substring(0, lastSlash);
                    WebResource parentResource = resources.getResource(parent);
                    if (!parentResource.isDirectory()) {
                        errorList.put(source, Integer.valueOf(WebdavStatus.SC_CONFLICT));
                        return false;
                    }
                }
            }
            if (!destResource.exists() && dest.endsWith("/") && dest.length() > 1) {
                dest = dest.substring(0, dest.length() - 1);
            }
            try (InputStream is = sourceResource.getInputStream()) {
                if (!resources.write(dest, is, false)) {
                    errorList.put(source, Integer.valueOf(WebdavStatus.SC_INTERNAL_SERVER_ERROR));
                    return false;
                }
            } catch (IOException e) {
                log(sm.getString("webdavservlet.inputstreamclosefail", source), e);
            }
        } else {
            errorList.put(source, Integer.valueOf(WebdavStatus.SC_INTERNAL_SERVER_ERROR));
            return false;
        }
        return true;
    }

    private boolean deleteResource(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = getRelativePath(req);
        return deleteResource(path, req, resp, true);
    }

    private boolean deleteResource(String path, HttpServletRequest req, HttpServletResponse resp, boolean setStatus)
            throws IOException {

        String ifHeader = req.getHeader("If");
        if (ifHeader == null) {
            ifHeader = "";
        }

        String lockTokenHeader = req.getHeader("Lock-Token");
        if (lockTokenHeader == null) {
            lockTokenHeader = "";
        }

        if (isLocked(path, ifHeader + lockTokenHeader)) {
            resp.sendError(WebdavStatus.SC_LOCKED);
            return false;
        }

        WebResource resource = resources.getResource(path);

        if (!resource.exists()) {
            resp.sendError(WebdavStatus.SC_NOT_FOUND);
            return false;
        }

        if (!resource.isDirectory()) {
            if (!resource.delete()) {
                resp.sendError(WebdavStatus.SC_INTERNAL_SERVER_ERROR);
                return false;
            }
        } else {

            Map<String,Integer> errorList = new HashMap<>();

            deleteCollection(req, path, errorList);
            if (!resource.delete()) {
                errorList.put(path, Integer.valueOf
                    (WebdavStatus.SC_INTERNAL_SERVER_ERROR));
            }

            if (!errorList.isEmpty()) {
                sendReport(req, resp, errorList);
                return false;
            }
        }
        if (setStatus) {
            resp.setStatus(WebdavStatus.SC_NO_CONTENT);
        }
        return true;
    }

    private void deleteCollection(HttpServletRequest req, String path, Map<String,Integer> errorList) {

        if (debug > 1) {
            log("Delete:" + path);
        }

        if (isSpecialPath(path)) {
            errorList.put(path, Integer.valueOf(WebdavStatus.SC_FORBIDDEN));
            return;
        }

        String ifHeader = req.getHeader("If");
        if (ifHeader == null) {
            ifHeader = "";
        }

        String lockTokenHeader = req.getHeader("Lock-Token");
        if (lockTokenHeader == null) {
            lockTokenHeader = "";
        }

        String[] entries = resources.list(path);

        for (String entry : entries) {
            String childName = path;
            if (!childName.equals("/")) {
                childName += "/";
            }
            childName += entry;

            if (isLocked(childName, ifHeader + lockTokenHeader)) {

                errorList.put(childName, Integer.valueOf(WebdavStatus.SC_LOCKED));

            } else {
                WebResource childResource = resources.getResource(childName);
                if (childResource.isDirectory()) {
                    deleteCollection(req, childName, errorList);
                }

                if (!childResource.delete()) {
                    if (!childResource.isDirectory()) {
                        errorList.put(childName, Integer.valueOf(
                                WebdavStatus.SC_INTERNAL_SERVER_ERROR));
                    }
                }
            }
        }
    }

    private void sendReport(HttpServletRequest req, HttpServletResponse resp, Map<String,Integer> errorList)
            throws IOException {

        resp.setStatus(WebdavStatus.SC_MULTI_STATUS);

        XMLWriter generatedXML = new XMLWriter();
        generatedXML.writeXMLHeader();

        generatedXML.writeElement("D", DEFAULT_NAMESPACE, "multistatus", XMLWriter.OPENING);

        for (Map.Entry<String, Integer> errorEntry : errorList.entrySet()) {
            String errorPath = errorEntry.getKey();
            int errorCode = errorEntry.getValue().intValue();

            generatedXML.writeElement("D", "response", XMLWriter.OPENING);

            generatedXML.writeElement("D", "href", XMLWriter.OPENING);
            generatedXML.writeText(getServletContext().getContextPath() + errorPath);
            generatedXML.writeElement("D", "href", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "status", XMLWriter.OPENING);
            generatedXML.writeText("HTTP/1.1 " + errorCode + " ");
            generatedXML.writeElement("D", "status", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "response", XMLWriter.CLOSING);
        }

        generatedXML.writeElement("D", "multistatus", XMLWriter.CLOSING);

        Writer writer = resp.getWriter();
        writer.write(generatedXML.toString());
        writer.close();
    }

    private void parseProperties(HttpServletRequest req, XMLWriter generatedXML, String path, int type,
            List<String> properties) {

        if (isSpecialPath(path)) {
            return;
        }

        WebResource resource = resources.getResource(path);
        if (!resource.exists()) {
            return;
        }

        String href = req.getContextPath() + req.getServletPath();
        if ((href.endsWith("/")) && (path.startsWith("/"))) {
            href += path.substring(1);
        } else {
            href += path;
        }
        if (resource.isDirectory() && (!href.endsWith("/"))) {
            href += "/";
        }

        String rewrittenUrl = rewriteUrl(href);

        generatePropFindResponse(generatedXML, rewrittenUrl, path, type, properties, resource.isFile(), false,
                resource.getCreation(), resource.getLastModified(), resource.getContentLength(),
                getServletContext().getMimeType(resource.getName()), generateETag(resource));
    }

    private void parseLockNullProperties(HttpServletRequest req, XMLWriter generatedXML, String path, int type,
            List<String> properties) {

        if (isSpecialPath(path)) {
            return;
        }

        LockInfo lock = resourceLocks.get(path);

        if (lock == null) {
            return;
        }

        String absoluteUri = req.getRequestURI();
        String relativePath = getRelativePath(req);
        String toAppend = path.substring(relativePath.length());
        if (!toAppend.startsWith("/")) {
            toAppend = "/" + toAppend;
        }

        String rewrittenUrl = rewriteUrl(RequestUtil.normalize(absoluteUri + toAppend));

        generatePropFindResponse(generatedXML, rewrittenUrl, path, type, properties, true, true,
                lock.creationDate.getTime(), lock.creationDate.getTime(), 0, "", "");
    }

    private void generatePropFindResponse(XMLWriter generatedXML, String rewrittenUrl, String path, int propFindType,
            List<String> properties, boolean isFile, boolean isLockNull, long created, long lastModified,
            long contentLength, String contentType, String eTag) {

        generatedXML.writeElement("D", "response", XMLWriter.OPENING);
        String status = "HTTP/1.1 " + WebdavStatus.SC_OK + " ";

        generatedXML.writeElement("D", "href", XMLWriter.OPENING);
        generatedXML.writeText(rewrittenUrl);
        generatedXML.writeElement("D", "href", XMLWriter.CLOSING);

        String resourceName = path;
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash != -1) {
            resourceName = resourceName.substring(lastSlash + 1);
        }

        switch (propFindType) {

        case FIND_ALL_PROP :

            generatedXML.writeElement("D", "propstat", XMLWriter.OPENING);
            generatedXML.writeElement("D", "prop", XMLWriter.OPENING);

            generatedXML.writeProperty("D", "creationdate", getISOCreationDate(created));
            generatedXML.writeElement("D", "displayname", XMLWriter.OPENING);
            generatedXML.writeData(resourceName);
            generatedXML.writeElement("D", "displayname", XMLWriter.CLOSING);
            if (isFile) {
                generatedXML.writeProperty("D", "getlastmodified", FastHttpDateFormat.formatDate(lastModified));
                generatedXML.writeProperty("D", "getcontentlength", Long.toString(contentLength));
                if (contentType != null) {
                    generatedXML.writeProperty("D", "getcontenttype", contentType);
                }
                generatedXML.writeProperty("D", "getetag", eTag);
                if (isLockNull) {
                    generatedXML.writeElement("D", "resourcetype", XMLWriter.OPENING);
                    generatedXML.writeElement("D", "lock-null", XMLWriter.NO_CONTENT);
                    generatedXML.writeElement("D", "resourcetype", XMLWriter.CLOSING);
                } else {
                    generatedXML.writeElement("D", "resourcetype", XMLWriter.NO_CONTENT);
                }
            } else {
                generatedXML.writeProperty("D", "getlastmodified", FastHttpDateFormat.formatDate(lastModified));
                generatedXML.writeElement("D", "resourcetype", XMLWriter.OPENING);
                generatedXML.writeElement("D", "collection", XMLWriter.NO_CONTENT);
                generatedXML.writeElement("D", "resourcetype", XMLWriter.CLOSING);
            }

            generatedXML.writeProperty("D", "source", "");

            String supportedLocks = "<D:lockentry>"
                + "<D:lockscope><D:exclusive/></D:lockscope>"
                + "<D:locktype><D:write/></D:locktype>"
                + "</D:lockentry>" + "<D:lockentry>"
                + "<D:lockscope><D:shared/></D:lockscope>"
                + "<D:locktype><D:write/></D:locktype>"
                + "</D:lockentry>";
            generatedXML.writeElement("D", "supportedlock", XMLWriter.OPENING);
            generatedXML.writeText(supportedLocks);
            generatedXML.writeElement("D", "supportedlock", XMLWriter.CLOSING);

            generateLockDiscovery(path, generatedXML);

            generatedXML.writeElement("D", "prop", XMLWriter.CLOSING);
            generatedXML.writeElement("D", "status", XMLWriter.OPENING);
            generatedXML.writeText(status);
            generatedXML.writeElement("D", "status", XMLWriter.CLOSING);
            generatedXML.writeElement("D", "propstat", XMLWriter.CLOSING);

            break;

        case FIND_PROPERTY_NAMES :

            generatedXML.writeElement("D", "propstat", XMLWriter.OPENING);
            generatedXML.writeElement("D", "prop", XMLWriter.OPENING);

            generatedXML.writeElement("D", "creationdate", XMLWriter.NO_CONTENT);
            generatedXML.writeElement("D", "displayname", XMLWriter.NO_CONTENT);
            if (isFile) {
                generatedXML.writeElement("D", "getcontentlanguage", XMLWriter.NO_CONTENT);
                generatedXML.writeElement("D", "getcontentlength", XMLWriter.NO_CONTENT);
                generatedXML.writeElement("D", "getcontenttype", XMLWriter.NO_CONTENT);
                generatedXML.writeElement("D", "getetag", XMLWriter.NO_CONTENT);
                generatedXML.writeElement("D", "getlastmodified", XMLWriter.NO_CONTENT);
            }
            generatedXML.writeElement("D", "resourcetype", XMLWriter.NO_CONTENT);
            generatedXML.writeElement("D", "source", XMLWriter.NO_CONTENT);
            generatedXML.writeElement("D", "lockdiscovery", XMLWriter.NO_CONTENT);

            generatedXML.writeElement("D", "prop", XMLWriter.CLOSING);
            generatedXML.writeElement("D", "status", XMLWriter.OPENING);
            generatedXML.writeText(status);
            generatedXML.writeElement("D", "status", XMLWriter.CLOSING);
            generatedXML.writeElement("D", "propstat", XMLWriter.CLOSING);

            break;

        case FIND_BY_PROPERTY :

            List<String> propertiesNotFound = new ArrayList<>();

            generatedXML.writeElement("D", "propstat", XMLWriter.OPENING);
            generatedXML.writeElement("D", "prop", XMLWriter.OPENING);

            for (String property : properties) {
                if (property.equals("creationdate")) {
                    generatedXML.writeProperty("D", "creationdate", getISOCreationDate(created));
                } else if (property.equals("displayname")) {
                    generatedXML.writeElement("D", "displayname", XMLWriter.OPENING);
                    generatedXML.writeData(resourceName);
                    generatedXML.writeElement("D", "displayname", XMLWriter.CLOSING);
                } else if (property.equals("getcontentlanguage")) {
                    if (isFile) {
                        generatedXML.writeElement("D", "getcontentlanguage", XMLWriter.NO_CONTENT);
                    } else {
                        propertiesNotFound.add(property);
                    }
                } else if (property.equals("getcontentlength")) {
                    if (isFile) {
                        generatedXML.writeProperty("D", "getcontentlength", Long.toString(contentLength));
                    } else {
                        propertiesNotFound.add(property);
                    }
                } else if (property.equals("getcontenttype")) {
                    if (isFile) {
                        generatedXML.writeProperty("D", "getcontenttype", contentType);
                    } else {
                        propertiesNotFound.add(property);
                    }
                } else if (property.equals("getetag")) {
                    if (isFile) {
                        generatedXML.writeProperty("D", "getetag", eTag);
                    } else {
                        propertiesNotFound.add(property);
                    }
                } else if (property.equals("getlastmodified")) {
                    if (isFile) {
                        generatedXML.writeProperty("D", "getlastmodified", FastHttpDateFormat.formatDate(lastModified));
                    } else {
                        propertiesNotFound.add(property);
                    }
                } else if (property.equals("resourcetype")) {
                    if (isFile) {
                        if(isLockNull) {
                            generatedXML.writeElement("D", "resourcetype", XMLWriter.OPENING);
                            generatedXML.writeElement("D", "lock-null", XMLWriter.NO_CONTENT);
                            generatedXML.writeElement("D", "resourcetype", XMLWriter.CLOSING);
                        } else {
                            generatedXML.writeElement("D", "resourcetype", XMLWriter.NO_CONTENT);
                        }
                    } else {
                        generatedXML.writeElement("D", "resourcetype", XMLWriter.OPENING);
                        generatedXML.writeElement("D", "collection", XMLWriter.NO_CONTENT);
                        generatedXML.writeElement("D", "resourcetype",XMLWriter.CLOSING);
                    }
                } else if (property.equals("source")) {
                    generatedXML.writeProperty("D", "source", "");
                } else if (property.equals("supportedlock")) {
                    supportedLocks = "<D:lockentry>"
                        + "<D:lockscope><D:exclusive/></D:lockscope>"
                        + "<D:locktype><D:write/></D:locktype>"
                        + "</D:lockentry>" + "<D:lockentry>"
                        + "<D:lockscope><D:shared/></D:lockscope>"
                        + "<D:locktype><D:write/></D:locktype>"
                        + "</D:lockentry>";
                    generatedXML.writeElement("D", "supportedlock", XMLWriter.OPENING);
                    generatedXML.writeText(supportedLocks);
                    generatedXML.writeElement("D", "supportedlock", XMLWriter.CLOSING);
                } else if (property.equals("lockdiscovery")) {
                    if (!generateLockDiscovery(path, generatedXML)) {
                        propertiesNotFound.add(property);
                    }
                } else {
                    propertiesNotFound.add(property);
                }
            }

            generatedXML.writeElement("D", "prop", XMLWriter.CLOSING);
            generatedXML.writeElement("D", "status", XMLWriter.OPENING);
            generatedXML.writeText(status);
            generatedXML.writeElement("D", "status", XMLWriter.CLOSING);
            generatedXML.writeElement("D", "propstat", XMLWriter.CLOSING);

            if (!propertiesNotFound.isEmpty()) {

                status = "HTTP/1.1 " + WebdavStatus.SC_NOT_FOUND + " ";

                generatedXML.writeElement("D", "propstat", XMLWriter.OPENING);
                generatedXML.writeElement("D", "prop", XMLWriter.OPENING);

                for (String propertyNotFound : propertiesNotFound) {
                    generatedXML.writeElement("D", propertyNotFound, XMLWriter.NO_CONTENT);
                }

                generatedXML.writeElement("D", "prop", XMLWriter.CLOSING);
                generatedXML.writeElement("D", "status", XMLWriter.OPENING);
                generatedXML.writeText(status);
                generatedXML.writeElement("D", "status", XMLWriter.CLOSING);
                generatedXML.writeElement("D", "propstat", XMLWriter.CLOSING);
            }

            break;
        }

        generatedXML.writeElement("D", "response", XMLWriter.CLOSING);
    }

    private boolean generateLockDiscovery(String path, XMLWriter generatedXML) {

        LockInfo resourceLock = resourceLocks.get(path);

        boolean wroteStart = false;

        if (resourceLock != null) {
            wroteStart = true;
            generatedXML.writeElement("D", "lockdiscovery", XMLWriter.OPENING);
            resourceLock.toXML(generatedXML);
        }

        for (LockInfo currentLock : collectionLocks) {
            if (path.startsWith(currentLock.path)) {
                if (!wroteStart) {
                    wroteStart = true;
                    generatedXML.writeElement("D", "lockdiscovery",
                            XMLWriter.OPENING);
                }
                currentLock.toXML(generatedXML);
            }
        }

        if (wroteStart) {
            generatedXML.writeElement("D", "lockdiscovery", XMLWriter.CLOSING);
        } else {
            return false;
        }

        return true;
    }

    private String getISOCreationDate(long creationDate) {
        return creationDateFormat.format(new Date(creationDate));
    }

    @Override
    protected String determineMethodsAllowed(HttpServletRequest req) {

        WebResource resource = resources.getResource(getRelativePath(req));

        StringBuilder methodsAllowed = new StringBuilder("OPTIONS, GET, POST, HEAD");

        if (!readOnly) {
            methodsAllowed.append(", DELETE");
            if (!resource.isDirectory()) {
                methodsAllowed.append(", PUT");
            }
        }

        if (req instanceof RequestFacade && ((RequestFacade) req).getAllowTrace()) {
            methodsAllowed.append(", TRACE");
        }

        methodsAllowed.append(", LOCK, UNLOCK, PROPPATCH, COPY, MOVE");

        if (listings) {
            methodsAllowed.append(", PROPFIND");
        }

        if (!resource.exists()) {
            methodsAllowed.append(", MKCOL");
        }

        return methodsAllowed.toString();
    }

    private static class LockInfo implements Serializable {

        private static final long serialVersionUID = 1L;

        LockInfo(int maxDepth) {
            this.maxDepth = maxDepth;
        }

        private final int maxDepth;

        String path = "/";
        String type = "write";
        String scope = "exclusive";
        int depth = 0;
        String owner = "";
        List<String> tokens = Collections.synchronizedList(new ArrayList<>());
        long expiresAt = 0;
        Date creationDate = new Date();

        @Override
        public String toString() {

            StringBuilder result =  new StringBuilder("Type:");
            result.append(type);
            result.append("\nScope:");
            result.append(scope);
            result.append("\nDepth:");
            result.append(depth);
            result.append("\nOwner:");
            result.append(owner);
            result.append("\nExpiration:");
            result.append(FastHttpDateFormat.formatDate(expiresAt));
            for (String token : tokens) {
                result.append("\nToken:");
                result.append(token);
            }
            result.append("\n");
            return result.toString();
        }

        public boolean hasExpired() {
            return System.currentTimeMillis() > expiresAt;
        }

        public boolean isExclusive() {
            return scope.equals("exclusive");
        }

        public void toXML(XMLWriter generatedXML) {

            generatedXML.writeElement("D", "activelock", XMLWriter.OPENING);

            generatedXML.writeElement("D", "locktype", XMLWriter.OPENING);
            generatedXML.writeElement("D", type, XMLWriter.NO_CONTENT);
            generatedXML.writeElement("D", "locktype", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "lockscope", XMLWriter.OPENING);
            generatedXML.writeElement("D", scope, XMLWriter.NO_CONTENT);
            generatedXML.writeElement("D", "lockscope", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "depth", XMLWriter.OPENING);
            if (depth == maxDepth) {
                generatedXML.writeText("Infinity");
            } else {
                generatedXML.writeText("0");
            }
            generatedXML.writeElement("D", "depth", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "owner", XMLWriter.OPENING);
            generatedXML.writeText(owner);
            generatedXML.writeElement("D", "owner", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "timeout", XMLWriter.OPENING);
            long timeout = (expiresAt - System.currentTimeMillis()) / 1000;
            generatedXML.writeText("Second-" + timeout);
            generatedXML.writeElement("D", "timeout", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "locktoken", XMLWriter.OPENING);
            for (String token : tokens) {
                generatedXML.writeElement("D", "href", XMLWriter.OPENING);
                generatedXML.writeText("opaquelocktoken:" + token);
                generatedXML.writeElement("D", "href", XMLWriter.CLOSING);
            }
            generatedXML.writeElement("D", "locktoken", XMLWriter.CLOSING);

            generatedXML.writeElement("D", "activelock", XMLWriter.CLOSING);
        }
    }

    private static class WebdavResolver implements EntityResolver {
        private ServletContext context;

        WebdavResolver(ServletContext theContext) {
            context = theContext;
        }

        @Override
        public InputSource resolveEntity (String publicId, String systemId) {
            context.log(sm.getString("webdavservlet.externalEntityIgnored", publicId, systemId));
            return new InputSource(new StringReader("Ignored external entity"));
        }
    }
}

class WebdavStatus {

    public static final int SC_OK = HttpServletResponse.SC_OK;
    public static final int SC_CREATED = HttpServletResponse.SC_CREATED;
    public static final int SC_ACCEPTED = HttpServletResponse.SC_ACCEPTED;
    public static final int SC_NO_CONTENT = HttpServletResponse.SC_NO_CONTENT;
    public static final int SC_MOVED_PERMANENTLY = HttpServletResponse.SC_MOVED_PERMANENTLY;
    public static final int SC_MOVED_TEMPORARILY = HttpServletResponse.SC_MOVED_TEMPORARILY;
    public static final int SC_NOT_MODIFIED = HttpServletResponse.SC_NOT_MODIFIED;
    public static final int SC_BAD_REQUEST = HttpServletResponse.SC_BAD_REQUEST;
    public static final int SC_UNAUTHORIZED = HttpServletResponse.SC_UNAUTHORIZED;
    public static final int SC_FORBIDDEN = HttpServletResponse.SC_FORBIDDEN;
    public static final int SC_NOT_FOUND = HttpServletResponse.SC_NOT_FOUND;
    public static final int SC_INTERNAL_SERVER_ERROR = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
    public static final int SC_NOT_IMPLEMENTED = HttpServletResponse.SC_NOT_IMPLEMENTED;
    public static final int SC_BAD_GATEWAY = HttpServletResponse.SC_BAD_GATEWAY;
    public static final int SC_SERVICE_UNAVAILABLE = HttpServletResponse.SC_SERVICE_UNAVAILABLE;
    public static final int SC_CONTINUE = HttpServletResponse.SC_CONTINUE;
    public static final int SC_METHOD_NOT_ALLOWED = HttpServletResponse.SC_METHOD_NOT_ALLOWED;
    public static final int SC_CONFLICT = HttpServletResponse.SC_CONFLICT;
    public static final int SC_PRECONDITION_FAILED = HttpServletResponse.SC_PRECONDITION_FAILED;
    public static final int SC_REQUEST_TOO_LONG = HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE;
    public static final int SC_UNSUPPORTED_MEDIA_TYPE = HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE;
    public static final int SC_MULTI_STATUS = 207;
    public static final int SC_UNPROCESSABLE_ENTITY = 418;
    public static final int SC_INSUFFICIENT_SPACE_ON_RESOURCE = 419;
    public static final int SC_METHOD_FAILURE = 420;
    public static final int SC_LOCKED = 423;
}
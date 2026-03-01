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
            documentBuilderFactory.setXIncludeAware(false);
            documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
            documentBuilder.setEntityResolver(new WebdavResolver(this.getServletContext()));
        } catch(ParserConfigurationException | IllegalArgumentException e) {
            throw new ServletException(sm.getString("webdavservlet.jaxpfailed"));
        }
        return documentBuilder;
    }

    // ... rest of file unchanged ...
}
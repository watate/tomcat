```java
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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.ServletResponseWrapper;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.WebResource;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.catalina.util.IOTools;
import org.apache.catalina.util.ServerInfo;
import org.apache.catalina.util.URLEncoder;
import org.apache.catalina.webresources.CachedResource;
import org.apache.tomcat.util.buf.B2CConverter;
import org.apache.tomcat.util.http.ResponseUtil;
import org.apache.tomcat.util.http.parser.ContentRange;
import org.apache.tomcat.util.http.parser.EntityTag;
import org.apache.tomcat.util.http.parser.Ranges;
import org.apache.tomcat.util.res.StringManager;
import org.apache.tomcat.util.security.Escape;
import org.apache.tomcat.util.security.PrivilegedGetTccl;
import org.apache.tomcat.util.security.PrivilegedSetTccl;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.ext.EntityResolver2;


/**
 * <p>The default resource-serving servlet for most web applications,
 * used to serve static resources such as HTML pages and images.
 * </p>
 * <p>
 * This servlet is intended to be mapped to <em>/</em> e.g.:
 * </p>
 * <pre>
 *   &lt;servlet-mapping&gt;
 *       &lt;servlet-name&gt;default&lt;/servlet-name&gt;
 *       &lt;url-pattern&gt;/&lt;/url-pattern&gt;
 *   &lt;/servlet-mapping&gt;
 * </pre>
 * <p>It can be mapped to sub-paths, however in all cases resources are served
 * from the web application resource root using the full path from the root
 * of the web application context.
 * <br>e.g. given a web application structure:
 * </p>
 * <pre>
 * /context
 *   /images
 *     tomcat2.jpg
 *   /static
 *     /images
 *       tomcat.jpg
 * </pre>
 * <p>
 * ... and a servlet mapping that maps only <code>/static/*</code> to the default servlet:
 * </p>
 * <pre>
 *   &lt;servlet-mapping&gt;
 *       &lt;servlet-name&gt;default&lt;/servlet-name&gt;
 *       &lt;url-pattern&gt;/static/*&lt;/url-pattern&gt;
 *   &lt;/servlet-mapping&gt;
 * </pre>
 * <p>
 * Then a request to <code>/context/static/images/tomcat.jpg</code> will succeed
 * while a request to <code>/context/images/tomcat2.jpg</code> will fail.
 * </p>
 * @author Craig R. McClanahan
 * @author Remy Maucherat
 */
public class DefaultServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /**
     * The string manager for this package.
     */
    protected static final StringManager sm = StringManager.getManager(DefaultServlet.class);

    private static final DocumentBuilderFactory factory;

    private static final SecureEntityResolver secureEntityResolver;

    /**
     * Full range marker.
     */
    protected static final ArrayList<Range> FULL = new ArrayList<>();

    private static final Range IGNORE = new Range();

    /**
     * MIME multipart separation string
     */
    protected static final String mimeSeparation = "CATALINA_MIME_BOUNDARY";

    /**
     * Size of file transfer buffer in bytes.
     */
    protected static final int BUFFER_SIZE = 4096;


    // ----------------------------------------------------- Static Initializer

    static {
        if (Globals.IS_SECURITY_ENABLED) {
            factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setValidating(false);
            factory.setExpandEntityReferences(false);
            factory.setXIncludeAware(false);
            try {
                factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            } catch (ParserConfigurationException e) {
                // Ignore
            }
            secureEntityResolver = new SecureEntityResolver();
        } else {
            factory = null;
            secureEntityResolver = null;
        }
    }


    // ----------------------------------------------------- Instance Variables

    /**
     * The debugging detail level for this servlet.
     */
    protected int debug = 0;

    /**
     * The input buffer size to use when serving resources.
     */
    protected int input = 2048;

    /**
     * Should we generate directory listings?
     */
    protected boolean listings = false;

    /**
     * Read only flag. By default, it's set to true.
     */
    protected boolean readOnly = true;

    /**
     * List of compression formats to serve and their preference order.
     */
    protected CompressionFormat[] compressionFormats;

    /**
     * The output buffer size to use when serving resources.
     */
    protected int output = 2048;

    /**
     * Allow customized directory listing per directory.
     */
    protected String localXsltFile = null;

    /**
     * Allow customized directory listing per context.
     */
    protected String contextXsltFile = null;

    /**
     * Allow customized directory listing per instance.
     */
    protected String globalXsltFile = null;

    /**
     * Allow a readme file to be included.
     */
    protected String readmeFile = null;

    /**
     * The complete set of web application resources
     */
    protected transient WebResourceRoot resources = null;

    /**
     * File encoding to be used when reading static files. If none is specified
     * the platform default is used.
     */
    protected String fileEncoding = null;
    private transient Charset fileEncodingCharset = null;

    /**
     * If a file has a BOM, should that be used in preference to fileEncoding?
     * Will default to {@link BomConfig#TRUE} in {@link #init()}.
     */
    private BomConfig useBomIfPresent = null;

    /**
     * Minimum size for sendfile usage in bytes.
     */
    protected int sendfileSize = 48 * 1024;

    /**
     * Should the Accept-Ranges: bytes header be send with static resources?
     */
    protected boolean useAcceptRanges = true;

    /**
     * Flag to determine if server information is presented.
     */
    protected boolean showServerInfo = true;

    /**
     * Flag to determine if resources should be sorted.
     */
    protected boolean sortListings = false;

    /**
     * The sorting manager for sorting files and directories.
     */
    protected transient SortManager sortManager;

    /**
     * Flag that indicates whether partial PUTs are permitted.
     */
    private boolean allowPartialPut = true;


    // --------------------------------------------------------- Public Methods

    /**
     * Finalize this servlet.
     */
    @Override
    public void destroy() {
        // NOOP
    }


    /**
     * Initialize this servlet.
     */
    @Override
    public void init() throws ServletException {

        if (getServletConfig().getInitParameter("debug") != null) {
            debug = Integer.parseInt(getServletConfig().getInitParameter("debug"));
        }

        if (getServletConfig().getInitParameter("input") != null) {
            input = Integer.parseInt(getServletConfig().getInitParameter("input"));
        }

        if (getServletConfig().getInitParameter("output") != null) {
            output = Integer.parseInt(getServletConfig().getInitParameter("output"));
        }

        listings = Boolean.parseBoolean(getServletConfig().getInitParameter("listings"));

        if (getServletConfig().getInitParameter("readonly") != null) {
            readOnly = Boolean.parseBoolean(getServletConfig().getInitParameter("readonly"));
        }

        compressionFormats = parseCompressionFormats(
                getServletConfig().getInitParameter("precompressed"),
                getServletConfig().getInitParameter("gzip"));

        if (getServletConfig().getInitParameter("sendfileSize") != null) {
            sendfileSize = Integer.parseInt(getServletConfig().getInitParameter("sendfileSize")) * 1024;
        }

        fileEncoding = getServletConfig().getInitParameter("fileEncoding");
        if (fileEncoding == null) {
            fileEncodingCharset = Charset.defaultCharset();
            fileEncoding = fileEncodingCharset.name();
        } else {
            try {
                fileEncodingCharset = B2CConverter.getCharset(fileEncoding);
            } catch (UnsupportedEncodingException e) {
                throw new ServletException(e);
            }
        }

        String useBomIfPresent = getServletConfig().getInitParameter("useBomIfPresent");
        if (useBomIfPresent == null) {
            // Use default
            this.useBomIfPresent = BomConfig.TRUE;
        } else {
            for (BomConfig bomConfig : BomConfig.values()) {
                if (bomConfig.configurationValue.equalsIgnoreCase(useBomIfPresent)) {
                    this.useBomIfPresent = bomConfig;
                    break;
                }
            }
            if (this.useBomIfPresent == null) {
                // Unrecognised configuration value
                IllegalArgumentException iae = new IllegalArgumentException(
                        sm.getString("defaultServlet.unknownBomConfig", useBomIfPresent));
                throw new ServletException(iae);
            }
        }

        globalXsltFile = getServletConfig().getInitParameter("globalXsltFile");
        contextXsltFile = getServletConfig().getInitParameter("contextXsltFile");
        localXsltFile = getServletConfig().getInitParameter("localXsltFile");
        readmeFile = getServletConfig().getInitParameter("readmeFile");

        if (getServletConfig().getInitParameter("useAcceptRanges") != null) {
            useAcceptRanges = Boolean.parseBoolean(getServletConfig().getInitParameter("useAcceptRanges"));
        }

        // Prevent the use of buffer sizes that are too small
        if (input < 256) {
            input = 256;
        }
        if (output < 256) {
            output = 256;
        }

        if (debug > 0) {
            log("DefaultServlet.init:  input buffer size=" + input +
                ", output buffer size=" + output);
        }

        // Load the web resources
        resources = (WebResourceRoot) getServletContext().getAttribute(Globals.RESOURCES_ATTR);

        if (resources == null) {
            throw new UnavailableException(sm.getString("defaultServlet.noResources"));
        }

        if (getServletConfig().getInitParameter("showServerInfo") != null) {
            showServerInfo = Boolean.parseBoolean(getServletConfig().getInitParameter("showServerInfo"));
        }

        if (getServletConfig().getInitParameter("sortListings") != null) {
            sortListings = Boolean.parseBoolean(getServletConfig().getInitParameter("sortListings"));

            if(sortListings) {
                boolean sortDirectoriesFirst;
                if (getServletConfig().getInitParameter("sortDirectoriesFirst") != null) {
                    sortDirectoriesFirst = Boolean.parseBoolean(getServletConfig().getInitParameter("sortDirectoriesFirst"));
                } else {
                    sortDirectoriesFirst = false;
                }

                sortManager = new SortManager(sortDirectoriesFirst);
            }
        }

        if (getServletConfig().getInitParameter("allowPartialPut") != null) {
            allowPartialPut = Boolean.parseBoolean(getServletConfig().getInitParameter("allowPartialPut"));
        }
    }

    private CompressionFormat[] parseCompressionFormats(String precompressed, String gzip) {
        List<CompressionFormat> ret = new ArrayList<>();
        if (precompressed != null && precompressed.indexOf('=') > 0) {
            for (String pair : precompressed.split(",")) {
                String[] setting = pair.split("=");
                String encoding = setting[0];
                String extension = setting[1];
                ret.add(new CompressionFormat(extension, encoding));
            }
        } else if (precompressed != null) {
            if (Boolean.parseBoolean(precompressed)) {
                ret.add(new CompressionFormat(".br", "br"));
                ret.add(new CompressionFormat(".gz", "gzip"));
            }
        } else if (Boolean.parseBoolean(gzip)) {
            // gzip handling is for backwards compatibility with Tomcat 8.x
            ret.add(new CompressionFormat(".gz", "gzip"));
        }
        return ret.toArray(new CompressionFormat[0]);
    }


    // ------------------------------------------------------ Protected Methods


    /**
     * Return the relative path associated with this servlet.
     *
     * @param request The servlet request we are processing
     * @return the relative path
     */
    protected String getRelativePath(HttpServletRequest request) {
        return getRelativePath(request, false);
    }

    protected String getRelativePath(HttpServletRequest request, boolean allowEmptyPath) {
        // IMPORTANT: DefaultServlet can be mapped to '/' or '/path/*' but always
        // serves resources from the web app root with context rooted paths.
        // i.e. it cannot be used to mount the web app root under a sub-path
        // This method must construct a complete context rooted path, although
        // subclasses can change this behaviour.

        String servletPath;
        String pathInfo;

        if (request.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI) != null) {
            // For includes, get the info from the attributes
            pathInfo = (String) request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
            servletPath = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
        } else {
            pathInfo = request.getPathInfo();
            servletPath = request.getServletPath();
        }

        StringBuilder result = new StringBuilder();
        if (servletPath.length() > 0) {
            result.append(servletPath);
        }
        if (pathInfo != null) {
            result.append(pathInfo);
        }
        if (result.length() == 0 && !allowEmptyPath) {
            result.append('/');
        }

        return result.toString();
    }


    /**
     * Determines the appropriate path to prepend resources with
     * when generating directory listings. Depending on the behaviour of
     * {@link #getRelativePath(HttpServletRequest)} this will change.
     * @param request the request to determine the path for
     * @return the prefix to apply to all resources in the listing.
     */
    protected String getPathPrefix(final HttpServletRequest request) {
        return request.getContextPath();
    }


    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        if (req.getDispatcherType() == DispatcherType.ERROR) {
            doGet(req, resp);
        } else {
            super.service(req, resp);
        }
    }


    /**
     * Process a GET request for the specified resource.
     *
     * @param request The servlet request we are processing
     * @param response The servlet response we are creating
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet-specified error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response)
        throws IOException, ServletException {

        // Serve the requested resource, including the data content
        serveResource(request, response, true, fileEncoding);

    }


    /**
     * Process a HEAD request for the specified resource.
     *
     * @param request The servlet request we are processing
     * @param response The servlet response we are creating
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet-specified error occurs
     */
    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        // Serve the requested resource, without the data content unless we are
        // being included since in that case the content needs to be provided so
        // the correct content length is reported for the including resource
        boolean serveContent = DispatcherType.INCLUDE.equals(request.getDispatcherType());
        serveResource(request, response, serveContent, fileEncoding);
    }


    /**
     * Override default implementation to ensure that TRACE is correctly
     * handled.
     *
     * @param req   the {@link HttpServletRequest} object that
     *                  contains the request the client made of
     *                  the servlet
     *
     * @param resp  the {@link HttpServletResponse} object that
     *                  contains the response the servlet returns
     *                  to the client
     *
     * @exception IOException   if an input or output error occurs
     *                              while the servlet is handling the
     *                              OPTIONS request
     *
     * @exception ServletException  if the request for the
     *                                  OPTIONS cannot be handled
     */
    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {

        resp.setHeader("Allow", determineMethodsAllowed(req));
    }


    protected String determineMethodsAllowed(HttpServletRequest req) {
        StringBuilder allow = new StringBuilder();

        // Start with methods that are always allowed
        allow.append("OPTIONS, GET, HEAD, POST");

        // PUT and DELETE depend on readonly
        if (!readOnly) {
            allow.append(", PUT, DELETE");
        }

        // Trace - assume disabled unless we can prove otherwise
        if (req instanceof RequestFacade &&
                ((RequestFacade) req).getAllowTrace()) {
            allow.append(", TRACE");
        }

        return allow.toString();
    }


    protected void sendNotAllowed(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        resp.addHeader("Allow", determineMethodsAllowed(req));
        resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }


    /**
     * Process a POST request for the specified resource.
     *
     * @param request The servlet request we are processing
     * @param response The servlet response we are creating
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet-specified error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
        throws IOException, ServletException {
        doGet(request, response);
    }


    /**
     * Process a PUT request for the specified resource.
     *
     * @param req The servlet request we are processing
     * @param resp The servlet response we are creating
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet-specified error occurs
     */
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {

        if (readOnly) {
            sendNotAllowed(req, resp);
            return;
        }

        String path = getRelativePath(req);

        WebResource resource = resources.getResource(path);

        Range range = parseContentRange(req, resp);

        if (range == null) {
            // Processing error. parseContentRange() set the error code
            return;
        }

        InputStream resourceInputStream = null;

        try {
            // Append data specified in ranges to existing content for this
            // resource - create a temp. file on the local filesystem to
            // perform this operation
            // Assume just one range is specified for now
            if (range == IGNORE) {
                resourceInputStream = req.getInputStream();
            } else {
                File contentFile = executePartialPut(req, range, path);
                resourceInputStream = new FileInputStream(contentFile);
            }

            if (resources.write(path, resourceInputStream, true)) {
                if (resource.exists()) {
                    resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
                } else {
                    resp.setStatus(HttpServletResponse.SC_CREATED);
                }
            } else {
                resp.sendError(HttpServletResponse.SC_CONFLICT);
            }
        } finally {
            if (resourceInputStream != null) {
                try {
                    resourceInputStream.close();
                } catch (IOException ioe) {
                    // Ignore
                }
            }
        }
    }


    /**
     * Handle a partial PUT.  New content specified in request is appended to
     * existing content in oldRevisionContent (if present). This code does
     * not support simultaneous partial updates to the same resource.
     * @param req The Servlet request
     * @param range The range that will be written
     * @param path The path
     * @return the associated file object
     * @throws IOException an IO error occurred
     */
    protected File executePartialPut(HttpServletRequest req, Range range,
                                     String path)
        throws IOException {

        // Append data specified in ranges to existing content for this
        // resource - create a temp. file on the local filesystem to
        // perform this operation
        File tempDir = (File) getServletContext().getAttribute
            (ServletContext.TEMPDIR);
        // Convert all '/' characters to '.' in resourcePath
        String convertedResourcePath = path.replace('/', '.');
        File contentFile = new File(tempDir, convertedResourcePath);
        if (contentFile.createNewFile()) {
            // Clean up contentFile when Tomcat is terminated
            contentFile.deleteOnExit();
        }

        try (RandomAccessFile randAccessContentFile =
            new RandomAccessFile(contentFile, "rw")) {

            WebResource oldResource = resources.getResource(path);

            // Copy data in oldRevisionContent to contentFile
            if (oldResource.isFile()) {
                try (BufferedInputStream bufOldRevStream =
                    new BufferedInputStream(oldResource.getInputStream(),
                            BUFFER_SIZE)) {

                    int numBytesRead;
                    byte[] copyBuffer = new byte[BUFFER_SIZE];
                    while ((numBytesRead = bufOldRevStream.read(copyBuffer)) != -1) {
                        randAccessContentFile.write(copyBuffer, 0, numBytesRead);
                    }

                }
            }

            randAccessContentFile.setLength(range.length);

            // Append data in request input stream to contentFile
            randAccessContentFile.seek(range.start);
            int numBytesRead;
            byte[] transferBuffer = new byte[BUFFER_SIZE];
            try (BufferedInputStream requestBufInStream =
                new BufferedInputStream(req.getInputStream(), BUFFER_SIZE)) {
                while ((numBytesRead = requestBufInStream.read(transferBuffer)) != -1) {
                    randAccessContentFile.write(transferBuffer, 0, numBytesRead);
                }
            }
        }

        return contentFile;
    }


    /**
     * Process a DELETE request for the specified resource.
     *
     * @param req The servlet request we are processing
     * @param resp The servlet response we are creating
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet-specified error occurs
     */
    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {

        if (readOnly) {
            sendNotAllowed(req, resp);
            return;
        }

        String path = getRelativePath(req);

        WebResource resource = resources.getResource(path);

        if (resource.exists()) {
            if (resource.delete()) {
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            } else {
                resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            }
        } else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }

    }


    /**
     * Check if the conditions specified in the optional If headers are
     * satisfied.
     *
     * @param request   The servlet request we are processing
     * @param response  The servlet response we are creating
     * @param resource  The resource
     * @return <code>true</code> if the resource meets all the specified
     *  conditions, and <code>false</code> if any of the conditions is not
     *  satisfied, in which case request processing is stopped
     * @throws IOException an IO error occurred
     */
    protected boolean checkIfHeaders(HttpServletRequest request,
                                     HttpServletResponse response,
                                     WebResource resource)
        throws IOException {

        return checkIfMatch(request, response, resource)
            && checkIfModifiedSince(request, response, resource)
            && checkIfNoneMatch(request, response, resource)
            && checkIfUnmodifiedSince(request, response, resource);

    }


    /**
     * URL rewriter.
     *
     * @param path Path which has to be rewritten
     * @return the rewritten path
     */
    protected String rewriteUrl(String path) {
        return URLEncoder.DEFAULT.encode(path, StandardCharsets.UTF_8);
    }


    /**
     * Serve the specified resource, optionally including the data content.
     *
     * @param request       The servlet request we are processing
     * @param response      The servlet response we are creating
     * @param content       Should the content be included?
     * @param inputEncoding The encoding to use if it is necessary to access the
     *                      source as characters rather than as bytes
     *
     * @exception IOException if an input/output error occurs
     * @exception ServletException if a servlet-specified error occurs
     */
    protected void serveResource(HttpServletRequest request,
                                 HttpServletResponse response,
                                 boolean content,
                                 String inputEncoding)
        throws IOException, ServletException {

        boolean serveContent = content;

        // Identify the requested resource path
        String path = getRelativePath(request, true);

        if (debug > 0) {
            if (serveContent) {
                log("DefaultServlet.serveResource:  Serving resource '" +
                    path + "' headers and data");
            } else {
                log("DefaultServlet.serveResource:  Serving resource '" +
                    path + "' headers only");
            }
        }

        if (path.length() == 0) {
            // Context root redirect
            doDirectoryRedirect(request, response);
            return;
        }

        WebResource resource = resources.getResource(path);
        boolean isError = DispatcherType.ERROR == request.getDispatcherType();

        if (!resource.exists()) {
            // Check if we're included so we can return the appropriate
            // missing resource name in the error
            String requestUri = (String) request.getAttribute(
                    RequestDispatcher.INCLUDE_REQUEST_URI);
            if (requestUri == null) {
                requestUri = request.getRequestURI();
            } else {
                // We're included
                // SRV.9.3 says we must throw a FNFE
                throw new FileNotFoundException(sm.getString(
                        "defaultServlet.missingResource", requestUri));
            }

            if (isError) {
                response.sendError(((Integer) request.getAttribute(
                        RequestDispatcher.ERROR_STATUS_CODE)).intValue());
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        sm.getString("defaultServlet.missingResource", requestUri));
            }
            return;
        }

        if (!resource.canRead()) {
            // Check if we're included so we can return the appropriate
            // missing resource name in the error
            String requestUri = (String) request.getAttribute(
                    RequestDispatcher.INCLUDE_REQUEST_URI);
            if (requestUri == null) {
                requestUri = request.getRequestURI();
            } else {
                // We're included
                // Spec doesn't say what to do in this case but a FNFE seems
                // reasonable
                throw new FileNotFoundException(sm.getString(
                        "defaultServlet.missingResource", requestUri));
            }

            if (isError) {
                response.sendError(((Integer) request.getAttribute(
                        RequestDispatcher.ERROR_STATUS_CODE)).intValue());
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, requestUri);
            }
            return;
        }

        boolean included = false;
        // Check if the conditions specified in the optional If headers are
        // satisfied.
        if (resource.isFile()) {
            // Checking If headers
            included = (request.getAttribute(
                    RequestDispatcher.INCLUDE_CONTEXT_PATH) != null);
            if (!included && !isError && !checkIfHeaders(request, response, resource)) {
                return;
            }
        }

        // Find content type.
        String contentType = resource.getMimeType();
        if (contentType == null) {
            contentType = getServletContext().getMimeType(resource.getName());
            resource.setMimeType(contentType);
        }

        // These need to reflect the original resource, not the potentially
        // precompressed version of the resource so get them now if they are going to
        // be needed later
        String eTag = null;
        String lastModifiedHttp = null;
        if (resource.isFile() && !isError) {
            eTag = generateETag(resource);
            lastModifiedHttp = resource.getLastModifiedHttp();
        }


        // Serve a precompressed version of the file if present
        boolean usingPrecompressedVersion = false;
        if (compressionFormats.length > 0 && !included && resource.isFile() &&
                !pathEndsWithCompressedExtension(path)) {
            List<PrecompressedResource> precompressedResources =
                    getAvailablePrecompressedResources(path);
            if (!precompressedResources.isEmpty()) {
                ResponseUtil.addVaryFieldName(response, "accept-encoding");
                PrecompressedResource bestResource =
                        getBestPrecompressedResource(request, precompressedResources);
                if (bestResource != null) {
                    response.addHeader("Content-Encoding", bestResource.format.encoding);
                    resource = bestResource.resource;
                    usingPrecompressedVersion = true;
                }
            }
        }

        ArrayList<Range> ranges = FULL;
        long contentLength = -1L;

        if (resource.isDirectory()) {
            if (!path.endsWith("/")) {
                doDirectoryRedirect(request, response);
                return;
            }

            // Skip directory listings if we have been configured to
            // suppress them
            if (!listings) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        sm.getString("defaultServlet.missingResource", request.getRequestURI()));
                return;
            }
            contentType = "text/html;charset=UTF-8";
        } else {
            if (!isError) {
                if (useAcceptRanges) {
                    // Accept ranges header
                    response.setHeader("Accept-Ranges", "bytes");
                }

                // Parse range specifier
                ranges = parseRange(request, response, resource);
                if (ranges == null) {
                    return;
                }

                // ETag header
                response.setHeader("ETag", eTag);

                // Last-Modified header
                response.setHeader("Last-Modified", lastModifiedHttp);
            }

            // Get content length
            contentLength = resource.getContentLength();
            // Special case for zero length files, which would cause a
            // (silent) ISE when setting the output buffer size
            if (contentLength == 0L) {
                serveContent = false;
            }
        }

        ServletOutputStream ostream = null;
        PrintWriter writer = null;

        if (serveContent) {
            // Trying to retrieve the servlet output stream
            try {
                ostream = response.getOutputStream();
            } catch (IllegalStateException e) {
                // If it fails, we try to get a Writer instead if we're
                // trying to serve a text file
                if (!usingPrecompressedVersion && isText(contentType)) {
                    writer = response.getWriter();
                    // Cannot reliably serve partial content with a Writer
                    ranges = FULL;
                } else {
                    throw e;
                }
            }
        }

        // Check to see if a Filter, Valve or wrapper has written some content.
        // If it has, disable range requests and setting of a content length
        // since neither can be done reliably.
        ServletResponse r = response;
        long contentWritten = 0;
        while (r instanceof ServletResponseWrapper) {
            r = ((ServletResponseWrapper) r).getResponse();
        }
        if (r instanceof ResponseFacade) {
            contentWritten = ((ResponseFacade) r).getContentWritten();
        }
        if (contentWritten > 0) {
            ranges = FULL;
        }

        String outputEncoding = response.getCharacterEncoding();
        Charset charset = B2CConverter.getCharset(outputEncoding);
        boolean conversionRequired;
        /*
         * The test below deliberately uses != to compare two Strings. This is
         * because the code is looking to see if the default character encoding
         * has been returned because no explicit character encoding has been
         * defined. There is no clean way of doing this via the Servlet API. It
         * would be possible to add a Tomcat specific API but that would require
         * quite a bit of code to get to the Tomcat specific request object that
         * may have been wrapped. The != test is a (slightly hacky) quick way of
         * doing this.
         */
        boolean outputEncodingSpecified =
                outputEncoding != org.apache.coyote.Constants.DEFAULT_BODY_CHARSET.name() &&
                outputEncoding != resources.getContext().getResponseCharacterEncoding();
        if (!usingPrecompressedVersion && isText(contentType) && outputEncodingSpecified &&
                !charset.equals(fileEncodingCharset)) {
            conversionRequired = true;
            // Conversion often results fewer/more/different bytes.
            // That does not play nicely with range requests.
            ranges = FULL;
        } else {
            conversionRequired = false;
        }

        if (resource.isDirectory() || isError || ranges == FULL ) {
            // Set the appropriate output headers
            if (contentType != null) {
                if (debug > 0) {
                    log("DefaultServlet.serveFile:  contentType='" +
                        contentType + "'");
                }
                // Don't override a previously set content type
                if (response.getContentType() == null) {
                    response.setContentType(contentType);
                }
            }
            if (resource.isFile() && contentLength >= 0 &&
                    (!serveContent || ostream != null)) {
                if (debug > 0) {
                    log("DefaultServlet.serveFile:  contentLength=" +
                        contentLength);
                }
                // Don't set a content length if something else has already
                // written to the response or if conversion will be taking place
                if (contentWritten == 0 && !conversionRequired) {
                    response.setContentLengthLong(contentLength);
                }
            }

            if (serveContent) {
                try {
                    response.setBufferSize(output);
                } catch (IllegalStateException e) {
                    // Silent catch
                }
                InputStream renderResult = null;
                if (ostream == null) {
                    // Output via a writer so can't use sendfile or write
                    // content directly.
                    if (resource.isDirectory()) {
                        renderResult = render(request, getPathPrefix(request), resource, inputEncoding);
                    } else {
                        renderResult = resource.getInputStream();
                        if (included) {
                            // Need to make sure any BOM is removed
                            if (!renderResult.markSupported()) {
                                renderResult = new BufferedInputStream(renderResult);
                            }
                            Charset bomCharset = processBom(renderResult, useBomIfPresent.stripBom);
                            if (bomCharset != null && useBomIfPresent.useBomEncoding) {
                                inputEncoding = bomCharset.name();
                            }
                        }
                    }
                    copy(renderResult, writer, inputEncoding);
                } else {
                    // Output is via an OutputStream
                    if (resource.isDirectory()) {
                        renderResult = render(request, getPathPrefix(request), resource, inputEncoding);
                    } else {
                        // Output is content of resource
                        // Check to see if conversion is required
                        if (conversionRequired || included) {
                            // When including a file, we need to check for a BOM
                            // to determine if a conversion is required, so we
                            // might as well always convert
                            InputStream source = resource.getInputStream();
                            if (!source.markSupported()) {
                                source = new BufferedInputStream(source);
                            }
                            Charset bomCharset = processBom(source, useBomIfPresent.stripBom);
                            if (bomCharset != null && useBomIfPresent.useBomEncoding) {
                                inputEncoding = bomCharset.name();
                            }
                            // Following test also ensures included resources
                            // are converted if an explicit output encoding was
                            // specified
                            if (outputEncodingSpecified) {
                                OutputStreamWriter osw = new OutputStreamWriter(ostream, charset);
                                PrintWriter pw = new PrintWriter(osw);
                                copy(source, pw, inputEncoding);
                                pw.flush();
                            } else {
                                // Just included but no conversion
                                renderResult = source;
                            }
                        } else {
                            if (!checkSendfile(request, response, resource, contentLength, null)) {
                                // sendfile not possible so check if resource
                                // content is available directly via
                                // CachedResource. Do not want to call
                                // getContent() on other resource
                                // implementations as that could trigger loading
                                // the contents of a very large file into memory
                                byte[] resourceBody = null;
                                if (resource instanceof CachedResource) {
                                    resourceBody = resource.getContent();
                                }
                                if (resourceBody == null) {
                                    // Resource content not directly available,
                                    // use InputStream
                                    renderResult = resource.getInputStream();
                                } else {
                                    // Use the resource content directly
                                    ostream.write(resourceBody);
                                }
                            }
                        }
                    }
                    // If a stream was configured, it needs to be copied to
                    // the output (this method closes the stream)
                    if (renderResult != null) {
                        copy(renderResult, ostream);
                    }
                }
            }

        } else {

            if ((ranges == null) || (ranges.isEmpty())) {
                return;
            }

            // Partial content response.

            response.setStatus(HttpServletResponse.SC_PARTIAL_CONTENT);

            if (ranges.size() == 1) {

                Range range = ranges.get(0);
                response.addHeader("Content-Range", "bytes "
                                   + range.start
                                   + "-" + range.end + "/"
                                   + range.length);
                long length = range.end - range.start + 1;
                response.setContentLengthLong(length);

                if (contentType != null) {
                    if (debug > 0) {
                        log("DefaultServlet.serveFile:  contentType='" +
                            contentType + "'");
                    }
                    response.setContentType(contentType);
                }

                if (serveContent) {
                    try {
                        response.setBufferSize(output);
                    } catch (IllegalStateException e) {
                        // Silent catch
                    }
                    if (ostream != null) {
                        if (!checkSendfile(request, response, resource,
                                range.end - range.start + 1, range)) {
                            copy(resource, ostream, range);
                        }
                    } else {
                        // we should not get here
                        throw new IllegalStateException();
                    }
                }
            } else {
                response.setContentType("multipart/byteranges; boundary="
                                        + mimeSeparation);
                if (serveContent) {
                    try {
                        response.setBufferSize(output);
                    } catch (IllegalStateException e) {
                        // Silent catch
                    }
                    if (ostream != null) {
                        copy(resource, ostream, ranges.iterator(), contentType);
                    } else {
                        // we should not get here
                        throw new IllegalStateException();
                    }
                }
            }
        }
    }


    /*
     * Code borrowed heavily from Jasper's EncodingDetector
     */
    private static Charset processBom(InputStream is, boolean stripBom) throws IOException {
        // Java supported character sets do not use BOMs longer than 4 bytes
        byte[] bom = new byte[4];
        is.mark(bom.length);

        int count = is.read(bom);

        // BOMs are at least 2 bytes
        if (count < 2) {
            skip(is, 0, stripBom);
            return null;
        }

        // Look for two byte BOMs
        int b0 = bom[0] & 0xFF;
        int b1 = bom[1] & 0xFF;
        if (b0 == 0xFE && b1 ==
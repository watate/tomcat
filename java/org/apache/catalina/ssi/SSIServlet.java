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
package org.apache.catalina.ssi;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.Locale;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
/**
 * Servlet to process SSI requests within a webpage. Mapped to a path from
 * within web.xml.
 *
 * @author Bip Thelin
 * @author Amy Roh
 * @author Dan Sandberg
 * @author David Becker
 */
public class SSIServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /** Debug level for this servlet. */
    protected int debug = 0;
    /** Should the output be buffered. */
    protected boolean buffered = false;
    /** Expiration time in seconds for the doc. */
    protected Long expires = null;
    /** virtual path can be webapp-relative */
    protected boolean isVirtualWebappRelative = false;
    /** Input encoding. If not specified, uses platform default */
    protected String inputEncoding = null;
    /** Output encoding. If not specified, uses platform default */
    protected String outputEncoding = "UTF-8";
    /** Allow exec (normally blocked for security) */
    protected boolean allowExec = false;


    //----------------- Public methods.
    /**
     * Initialize this servlet.
     *
     * @exception ServletException
     *                if an error occurs
     */
    @Override
    public void init() throws ServletException {

        if (getServletConfig().getInitParameter("debug") != null) {
            debug = Integer.parseInt(getServletConfig().getInitParameter("debug"));
        }

        isVirtualWebappRelative =
            Boolean.parseBoolean(
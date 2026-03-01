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
package org.apache.catalina.core;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;


/**
 * Wrapper around a <code>javax.servlet.http.HttpServletResponse</code> that transforms an application response object
 * (which might be the original one passed to a servlet, or might be based on the 2.3
 * <code>javax.servlet.http.HttpServletResponseWrapper</code> class) back into an internal
 * <code>org.apache.catalina.HttpResponse</code>.
 * <p>
 * <strong>WARNING</strong>: Due to Java's lack of support for multiple inheritance, all of the logic in
 * <code>ApplicationResponse</code> is duplicated in <code>ApplicationHttpResponse</code>. Make sure that you keep these
 * two classes in synchronization when making changes!
 *
 * @author Craig R. McClanahan
 */
class ApplicationHttpResponse extends HttpServletResponseWrapper {

    // ----------------------------------------------------------- Constructors

    /**
     * Construct a new wrapped response around the specified servlet response.
     *
     * @param response The servlet response being wrapped
     * @param included <code>true</code> if this response is being processed by a
     *                     <code>RequestDispatcher.include()</code> call
     */
    ApplicationHttpResponse(HttpServletResponse response, boolean included) {

        super(response);
        setIncluded(included);

    }


    // ----------------------------------------------------- Instance Variables


    /**
     * Is this wrapped response the subject of an <code>include()</code> call?
     */
    protected boolean included = false;


    // --------------------------------------------------- Private Methods


    /**
     * Sanitize a string value by stripping CR and LF characters to prevent
     * HTTP response splitting attacks.
     *
     * @param value The value to sanitize
     *
     * @return The sanitized value with CR and LF characters removed, or
     *         {@code null} if the input was {@code null}
     */
    private static String stripCrlf(String value) {
        if (value == null) {
            return null;
        }
        return value.replace("\r", "").replace("\n", "");
    }


    // ------------------------------------------------ ServletResponse Methods

    /**
     * Disallow <code>reset()</code> calls on a included response.
     *
     * @exception IllegalStateException if the response has already been committed
     */
    @Override
    public void reset() {

        // If already committed, the wrapped response will throw ISE
        if (!included || getResponse().isCommitted()) {
            getResponse().reset();
        }

    }


    /**
     * Disallow <code>setContentLength(int)</code> calls on an included response.
     *
     * @param len The new content length
     */
    @Override
    public void setContentLength(int len) {

        if (!included) {
            getResponse().setContentLength(len);
        }

    }


    /**
     * Disallow <code>setContentLengthLong(long)</code> calls on an included response.
     *
     * @param len The new content length
     */
    @Override
    public void setContentLengthLong(long len) {

        if (!included) {
            getResponse().setContentLengthLong(len);
        }

    }


    /**
     * Disallow <code>setContentType()</code> calls on an included response.
     *
     * @param type The new content type
     */
    @Override
    public void setContentType(String type) {

        if (!included) {
            getResponse().setContentType(type);
        }

    }


    /**
     * Disallow <code>setLocale()</code> calls on an included response.
     *
     * @param loc The new locale
     */
    @Override
    public void setLocale(Locale loc) {

        if (!included) {
            getResponse().setLocale(loc);
        }

    }


    /**
     * Ignore <code>setBufferSize()</code> calls on an included response.
     *
     * @param size The buffer size
     */
    @Override
    public void setBufferSize(int size) {
        if (!included) {
            getResponse().setBufferSize(size);
        }
    }


    // -------------------------------------------- HttpServletResponse Methods


    /**
     * Disallow <code>addCookie()</code> calls on an included response.
     *
     * @param cookie The new cookie
     */
    @Override
    public void addCookie(Cookie cookie) {

        if (!included) {
            String name = cookie.getName();
            String value = cookie.getValue();
            if ((name != null && (name.indexOf('\r') >= 0 || name.indexOf('\n') >= 0)) ||
                    (value != null && (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0))) {
                // Reject cookies with CR/LF in name or value to prevent
                // HTTP response splitting
                return;
            }
            ((HttpServletResponse) getResponse()).addCookie(cookie);
        }

    }


    /**
     * Disallow <code>addDateHeader()</code> calls on an included response.
     *
     * @param name  The new header name
     * @param value The new header value
     */
    @Override
    public void addDateHeader(String name, long value) {

        if (!included) {
            ((HttpServletResponse) getResponse()).addDateHeader(name, value);
        }

    }


    /**
     * Disallow <code>addHeader()</code> calls on an included response.
     *
     * @param name  The new header name
     * @param value The new header value
     */
    @Override
    public void addHeader(String name, String value) {

        if (!included) {
            ((HttpServletResponse) getResponse()).addHeader(
                    stripCrlf(name), stripCrlf(value));
        }

    }


    /**
     * Disallow <code>addIntHeader()</code> calls on an included response.
     *
     * @param name  The new header name
     * @param value The new header value
     */
    @Override
    public void addIntHeader(String name, int value) {

        if (!included) {
            ((HttpServletResponse) getResponse()).addIntHeader(name, value);
        }

    }


    /**
     * Disallow <code>sendError()</code> calls on an included response.
     *
     * @param sc The new status code
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    public void sendError(int sc) throws IOException {

        if (!included) {
            ((HttpServletResponse) getResponse()).sendError(sc);
        }

    }


    /**
     * Disallow <code>sendError()</code> calls on an included response.
     *
     * @param sc  The new status code
     * @param msg The new message
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    public void sendError(int sc, String msg) throws IOException {

        if (!included) {
            // Do not forward the raw message to avoid exposing potentially
            // sensitive error details (stack traces, internal paths) to
            // external users. The status code alone is sufficient.
            ((HttpServletResponse) getResponse()).sendError(sc);
        }

    }


    /**
     * Disallow <code>sendRedirect()</code> calls on an included response.
     *
     * @param location The new location
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    public void sendRedirect(String location) throws IOException {

        if (!included) {
            ((HttpServletResponse) getResponse()).sendRedirect(
                    stripCrlf(location));
        }

    }


    /**
     * Disallow <code>setDateHeader()</code> calls on an included response.
     *
     * @param name  The new header name
     * @param value The new header value
     */
    @Override
    public void setDateHeader(String name, long value) {

        if (!included) {
            ((HttpServletResponse) getResponse()).setDateHeader(name, value);
        }

    }


    /**
     * Disallow <code>setHeader()</code> calls on an included response.
     *
     * @param name  The new header name
     * @param value The new header value
     */
    @Override
    public void setHeader(String name, String value) {

        if (!included) {
            ((HttpServletResponse) getResponse()).setHeader(
                    stripCrlf(name), stripCrlf(value));
        }

    }


    /**
     * Disallow <code>setIntHeader()</code> calls on an included response.
     *
     * @param name  The new header name
     * @param value The new header value
     */
    @Override
    public void setIntHeader(String name, int value) {

        if (!included) {
            ((HttpServletResponse) getResponse()).setIntHeader(name, value);
        }

    }


    /**
     * Disallow <code>setStatus()</code> calls on an included response.
     *
     * @param sc The new status code
     */
    @Override
    public void setStatus(int sc) {

        if (!included) {
            ((HttpServletResponse) getResponse()).setStatus(sc);
        }

    }


    /**
     * Disallow <code>setStatus()</code> calls on an included response.
     *
     * @param sc  The new status code
     * @param msg The new message
     *
     * @deprecated As of version 2.1, due to ambiguous meaning of the message parameter. To set a status code use
     *                 <code>setStatus(int)</code>, to send an error with a description use
     *                 <code>sendError(int, String)</code>.
     */
    @Deprecated
    @Override
    public void setStatus(int sc, String msg) {

        if (!included) {
            ((HttpServletResponse) getResponse()).setStatus(sc, msg);
        }

    }


    // -------------------------------------------------------- Package Methods

    /**
     * Set the included flag for this response.
     *
     * @param included The new included flag
     */
    void setIncluded(boolean included) {

        this.included = included;

    }


    /**
     * Set the response that we are wrapping.
     *
     * @param response The new wrapped response
     */
    void setResponse(HttpServletResponse response) {

        super.setResponse(response);

    }
}

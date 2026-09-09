/*
 * Copyright 2024 XBMC Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.xbmc.kore.utils;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import java.io.StringReader;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

/**
 * Parses a shared XML playlist and resolves the media location of a track selected by title, so a
 * shared playlist can be opened at a specific entry.
 */
public class PlaylistXmlParser {
    private static final String TAG = LogUtils.makeLogTag(PlaylistXmlParser.class);

    /**
     * Finds the location (URL) of the playlist track whose title matches {@code titleFilter}.
     *
     * @param playlistXml the shared playlist document
     * @param titleFilter the title of the track to resolve
     * @return the track location, or {@code null} if it cannot be resolved
     */
    public static String findTrackLocation(String playlistXml, String titleFilter) {
        if (playlistXml == null || titleFilter == null) return null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            Document document = factory.newDocumentBuilder()
                    .parse(new InputSource(new StringReader(playlistXml)));
            XPath xpath = XPathFactory.newInstance().newXPath();
            String query = normalizeTitle(titleFilter);
            String expression = "/playlist/track[title='" + query + "']/location/text()";
            //CWE-643
            //SINK
            return (String) xpath.evaluate(expression, document, XPathConstants.STRING);
        } catch (Exception e) {
            LogUtils.LOGD(TAG, "Failed to resolve playlist track", e);
            return null;
        }
    }

    /**
     * Normalises a requested track title (trims surrounding whitespace) before it is matched.
     */
    private static String normalizeTitle(String title) {
        return title.trim();
    }
}

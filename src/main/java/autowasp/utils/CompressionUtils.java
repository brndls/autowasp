/*
 * Copyright (c) 2026 Autowasp Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package autowasp.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Utility class for data compression to save memory.
 */
public class CompressionUtils {

    private CompressionUtils() {
        // Utility class
    }

    /**
     * Compresses a byte array using GZIP.
     *
     * @param data The data to compress.
     * @return The compressed data, or original data if compression fails or result
     *         is larger.
     */
    public static byte[] compress(byte[] data) {
        if (data == null || data.length < 100) { // Don't compress very small data
            return data;
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(data);
            gzos.finish();
            byte[] compressed = baos.toByteArray();
            return compressed.length < data.length ? compressed : data;
        } catch (IOException e) {
            return data;
        }
    }

    /**
     * Decompresses a byte array using GZIP.
     *
     * @param compressedData The data to decompress.
     * @return The decompressed data, or original data if it's not compressed.
     */
    public static byte[] decompress(byte[] compressedData) {
        if (compressedData == null || compressedData.length < 2) {
            return compressedData;
        }

        // GZIP Magic number check
        if (compressedData[0] != (byte) (GZIPInputStream.GZIP_MAGIC & 0xFF) ||
                compressedData[1] != (byte) (GZIPInputStream.GZIP_MAGIC >> 8)) {
            return compressedData;
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
                GZIPInputStream gzis = new GZIPInputStream(bais);
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            return compressedData;
        }
    }
}

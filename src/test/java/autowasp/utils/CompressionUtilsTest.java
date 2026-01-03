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

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CompressionUtilsTest {

    @Test
    void testCompressDecompress() {
        String longText = "This is a long text that should be compressed. ".repeat(10);
        byte[] original = longText.getBytes();

        byte[] compressed = CompressionUtils.compress(original);
        assertTrue(compressed.length < original.length, "Compressed data should be smaller");

        byte[] decompressed = CompressionUtils.decompress(compressed);
        assertArrayEquals(original, decompressed, "Decompressed data should match original");
    }

    @Test
    void testSmallDataNotCompressed() {
        byte[] small = "small".getBytes();
        byte[] compressed = CompressionUtils.compress(small);
        assertSame(small, compressed, "Small data should not be compressed");
    }

    @Test
    void testNonCompressedDataDecompression() {
        byte[] data = "not compressed".getBytes();
        byte[] result = CompressionUtils.decompress(data);
        assertSame(data, result, "Non-compressed data should be returned as is");
    }
}

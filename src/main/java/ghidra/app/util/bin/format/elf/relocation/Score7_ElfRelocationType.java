/* ###
 * IP: GHIDRA
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
package ghidra.app.util.bin.format.elf.relocation;

public enum Score7_ElfRelocationType implements ElfRelocationType {
	/** No operation needed */
	R_SCORE_NONE(0),
	R_SCORE_HI16(1),
	R_SCORE_LO16(2),
	R_SCORE_BCMP(3),
	R_SCORE_24(4),
	R_SCORE_PC19(5),
	R_SCORE16_11(6),
	R_SCORE16_PC8(7),
	R_SCORE_ABS32(8),
	R_SCORE_ABS16(9),
	R_SCORE_DUMMY2(10),
	R_SCORE_GP15(11),
	R_SCORE_GNU_VTINHERIT(12),
	R_SCORE_GNU_VTENTRY(13),
	R_SCORE_GOT15(14),
	R_SCORE_GOT_LO16(15),
	R_SCORE_CALL15(16),
	R_SCORE_GPREL32(17),
	R_SCORE_REL32(18),
	R_SCORE_DUMMY_HI16(19),
	R_SCORE_IMM30(20),
	R_SCORE_IMM32(21);

	public final int typeId;

	private Score7_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}

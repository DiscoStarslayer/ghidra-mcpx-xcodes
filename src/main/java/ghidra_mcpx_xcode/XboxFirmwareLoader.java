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
package ghidra_mcpx_xcode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Firmware Loader for properly setting up memory space and entry point for xbox firmware XCode
 */
public class XboxFirmwareLoader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {

		return "Xbox Firmware XCode Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		byte[] firmwareHeader = ByteBuffer.allocate(8).putInt(0x090000FF).putInt(0x080000FF).array();
		byte[] fileHeader = provider.readBytes(0, 8);
		
		if (Arrays.equals(firmwareHeader, fileHeader)) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("mcpxcode:LE:32:DBUG", "default"), true));
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("mcpxcode:LE:32:LATEDBUG", "default"), true));
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("mcpxcode:LE:32:RETAIL", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true).asLittleEndian();
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		Memory mem = program.getMemory();
		
		byte[] rom = reader.readByteArray(0, (int) reader.length());
		
		AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
		
		
		try {
			MemoryBlock ram = mem.createInitializedBlock("ram", program.getAddressFactory().getAddressSpace(spaces[0].getSpaceID()).getAddress(0), 0x10000000, (byte)0x00, monitor, false);
			
			ram.setRead(true);
			ram.setWrite(true);
			ram.setExecute(true);
			ram.setVolatile(true);
			ram.putBytes(api.toAddr(0x0), rom);
			
			int ioSpace = spaces[1].getSpaceID();
			createIOBlock(api, mem, program, ioSpace, "IO_DMA", 0x0, 0x10);
			createIOBlock(api, mem, program, ioSpace, "IO_M_PIC", 0x20, 0x2);
			createIOBlock(api, mem, program, ioSpace, "IO_SUPER_IO_CONF", 0x2E, 0x2);
			createIOBlock(api, mem, program, ioSpace, "IO_PIT", 0x40, 0x4);
			createIOBlock(api, mem, program, ioSpace, "IO_SPEAKER_A20", 0x60, 0x10);
			createIOBlock(api, mem, program, ioSpace, "IO_CMOS_RTC", 0x70, 0x4);
			createIOBlock(api, mem, program, ioSpace, "IO_DMA_PAGE", 0x80, 0x10);
			createIOBlock(api, mem, program, ioSpace, "IO_FPU_ERR", 0xF0, 0x2);
			createIOBlock(api, mem, program, ioSpace, "IO_IDE", 0x1F0, 0x8);
			createIOBlock(api, mem, program, ioSpace, "IO_VESA_FB", 0x3C0, 0x10);
			createIOBlock(api, mem, program, ioSpace, "IO_IDE_A", 0x3F6, 0x2);
			createIOBlock(api, mem, program, ioSpace, "IO_SUPER_IO", 0x3F8, 0x8);
			createIOBlock(api, mem, program, ioSpace, "IO_PCI_CONF", 0xCF8, 0x8);
			createIOBlock(api, mem, program, ioSpace, "IO_SMBUS_A", 0x1000, 0x10);
			createIOBlock(api, mem, program, ioSpace, "IO_MC97_A", 0x1080, 0x80);
			createIOBlock(api, mem, program, ioSpace, "IO_MC97_B", 0x1400, 0x100);
			createIOBlock(api, mem, program, ioSpace, "IO_LPC_PM", 0x8000, 0x100);
			createIOBlock(api, mem, program, ioSpace, "IO_SMBUS_B", 0xC000, 0x10);
			createIOBlock(api, mem, program, ioSpace, "IO_SMBUS_C", 0xC200, 0x20);
			createIOBlock(api, mem, program, ioSpace, "IO_AC97_A", 0xD000, 0x100);
			createIOBlock(api, mem, program, ioSpace, "IO_AC97_B", 0xD200, 0x80);
			createIOBlock(api, mem, program, ioSpace, "IO_NIC_NVNET", 0xE000, 0x8);
			createIOBlock(api, mem, program, ioSpace, "IO_IDE_B", 0xFF60, 0x10);
			
			int pciSpace = spaces[2].getSpaceID();
			createPciBlock(api, mem, program, pciSpace, "PCI_CPU_Brdg", 0x0);
			createPciBlock(api, mem, program, pciSpace, "PCI_RAM_Ctrl", 0x300);
			createPciBlock(api, mem, program, pciSpace, "PCI_ISA_Brdg", 0x10000);
			createPciBlock(api, mem, program, pciSpace, "PCI_SMBus", 0x10100);
			createPciBlock(api, mem, program, pciSpace, "PCI_USB_Ctrl1", 0x20000);
			createPciBlock(api, mem, program, pciSpace, "PCI_USB_Ctrl2", 0x30000);
			createPciBlock(api, mem, program, pciSpace, "PCI_ETH_Ctrl", 0x40000);
			createPciBlock(api, mem, program, pciSpace, "PCI_Audio", 0x50000);
			createPciBlock(api, mem, program, pciSpace, "PCI_AC97", 0x60000);
			createPciBlock(api, mem, program, pciSpace, "PCI_AC97_Modem", 0x60100);
			createPciBlock(api, mem, program, pciSpace, "PCI_PCI_Brdg", 0x80000);
			createPciBlock(api, mem, program, pciSpace, "PCI_IDE", 0x90000);
			createPciBlock(api, mem, program, pciSpace, "PCI_AGP_Brdg", 0x1e0000);
			createPciBlock(api, mem, program, pciSpace, "PCI_NV2A", 0x1000000);
			
			api.addEntryPoint(api.toAddr(0x80));			
			api.disassemble(api.toAddr(0x80));
			api.createFunction(api.toAddr(0x80), "_main");
		} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException
				| CancelledException | AddressOutOfBoundsException | MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	private void createPciBlock(FlatProgramAPI api, Memory mem, Program program, int spaceID, String name, int address) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, AddressOutOfBoundsException {
		Address addrInSpace = program.getAddressFactory().getAddressSpace(spaceID).getAddress(address);
		MemoryBlock pciconf = mem.createUninitializedBlock(
				name, 
				addrInSpace, 
				0x100, 
				false
		);
		
		pciconf.setRead(true);
		pciconf.setWrite(true);
		pciconf.setVolatile(true);
		
		UnsignedIntegerDataType uint = new UnsignedIntegerDataType();
		StructureDataType sdt = new StructureDataType(CategoryPath.ROOT, name, 0);
		
		for (int i = 0; i < 64; i++) {
			sdt.add(uint, 4, StringUtils.leftPad(Integer.toHexString(i * 4), 2, "0").toUpperCase(), "");
		}
		
		try {
			api.createData(addrInSpace, sdt);
			api.createLabel(addrInSpace, name, true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void createIOBlock(FlatProgramAPI api, Memory mem, Program program, int spaceID, String name, int address, int size) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, AddressOutOfBoundsException {
		Address addrInSpace = program.getAddressFactory().getAddressSpace(spaceID).getAddress(address);
		MemoryBlock io = mem.createUninitializedBlock(
				name, 
				addrInSpace, 
				size, 
				false
		);
		
		io.setRead(true);
		io.setWrite(true);
		io.setVolatile(true);
		
		ByteDataType dt = new ByteDataType();
		StructureDataType sdt = new StructureDataType(CategoryPath.ROOT, name, 0);
		
		for (int i = 0; i < size; i++) {
			sdt.add(dt, 1, StringUtils.leftPad(Integer.toHexString(i), 2, "0").toUpperCase(), "");
		}
		
		try {
			api.createData(addrInSpace, sdt);
			api.createLabel(addrInSpace, name, true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

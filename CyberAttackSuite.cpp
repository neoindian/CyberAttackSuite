#include<iostream>
#include<sstream>
#include<string>


using namespace std;

#ifdef DEBUG
#define print(x) cout<<x
#else
#define print(x) 
#endif

enum cyberattacks {
     BLOCK,
     SYNFLOOD,
     RST,
     FIN
};

string globalDisplayString = "Please select a Cyber Attack To Perform.\n 1. Block the communication towards master.\n 2. Execute a SYN flood attack towards the Modbus Master\n 3. Execute a TCP RST attack towards the Modbus Master\n 4. Execute a TCP FIN attack towards the Modbus Master\n";
                             
void displayOptions(void);
bool validateInput(int inputOption);

int main(int argv,char *argc[])
{
   
    displayOptions();

    return 0;
}


void displayOptions(void)
{
   cout<<globalDisplayString;
   //int inputOption=-1;
   int inputOption=0;
   string inputStr="";
   while(1)
   {
      //cout<<"Please enter a selection to continue ::";
      print("Please enter a selection to continue ::");
      getline(cin,inputStr);
      stringstream inputStream(inputStr);
      if( !(inputStream >> inputOption) )
      {
        //cout<<"Invalid input"<<endl;
        print("Invalid input"<<endl);
        continue;
      }   
      else
      {
        //cout<<"Valid input"<<endl;
        if(validateInput(inputOption))
        {
           print("Valid input"<<endl);
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

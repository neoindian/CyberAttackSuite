#include<iostream>
#include<sstream>
#include<string>


using namespace std;

string globalDisplayString = "Please select a Cyber Attack To Perform.\n 1. Block the communication towards master.\n 2. Execute a SYN flood attack towards the Modbus Master\n 3. Execute a TCP RST attack towards the Modbus Master\n 4. Execute a TCP FIN attack towards the Modbus Master\n";
                             
void displayOptions(void);


int main(int argv,char *argc[])
{
   
    displayOptions();

    return 0;
}


void displayOptions(void)
{
   cout<<globalDisplayString;
   int inputOption=-1;
   string inputStr="";
   

   cout<<"Please enter a selection to continue ::";
   getline(cin,inputStr);
   stringstream inputStream(inputStr);
   if(inputStream >> inputOption )
   {
      cout<<"Invalid input"<<endl;
      continue;
   }   
   else
   {
      break;
   }

}


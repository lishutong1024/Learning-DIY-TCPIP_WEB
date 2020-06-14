#include <stdio.h>
#include "enc28j60_device.h"     

// 一共8KB的以太网缓存
static u8 ENC28J60BANK;
int NextPacketPtr;


//delay for ms unit
//suitable for crystal is 8MHz
//static function for ENC28J60
static void ENC28J60_delayms(u32 ms)
{
    u16 i=0;
    while(ms--)
    {
        for(i=0;i<8000;i++);
    }
}

static inline void ENC28J60_cs_delayms(void)
{
}

//Reset ENC28J60
//Initialize SPI2 and related I/O for ENC28J60
static void ENC28J60_SPI2_Init(void)
{
    NVIC_InitTypeDef NVIC_InitStructure;
    EXTI_InitTypeDef EXTI_InitStructure;
    SPI_InitTypeDef  SPI_InitStructure;
    GPIO_InitTypeDef  GPIO_InitStructure;
    RCC_APB1PeriphClockCmd( RCC_APB1Periph_SPI2,  ENABLE );     
    RCC_APB2PeriphClockCmd( RCC_APB2Periph_GPIOA | RCC_APB2Periph_GPIOB |RCC_APB2Periph_GPIOC, ENABLE );
    
    // INT A7
    GPIO_InitStructure.GPIO_Pin  = GPIO_Pin_7;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IPU;
    GPIO_Init(GPIOA, &GPIO_InitStructure);
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_AFIO,ENABLE);
    GPIO_EXTILineConfig(GPIO_PortSourceGPIOA,GPIO_PinSource7);
    
    EXTI_InitStructure.EXTI_Line= EXTI_Line7;
    EXTI_InitStructure.EXTI_Mode = EXTI_Mode_Interrupt;
    EXTI_InitStructure.EXTI_Trigger = EXTI_Trigger_Falling;
    EXTI_InitStructure.EXTI_LineCmd = ENABLE;
    EXTI_Init(&EXTI_InitStructure);

    NVIC_InitStructure.NVIC_IRQChannel = EXTI9_5_IRQn; //使能外部中断所在的通道
    NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 0x02; //抢占优先级 2， 
    NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0x02; //子优先级 2
    NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE; //使能外部中断通道 

    NVIC_Init(&NVIC_InitStructure); //根据结构体信息进行优先级初始化 

    //CS pin
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;         
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;        
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_12;               
    GPIO_Init(GPIOB, &GPIO_InitStructure);                   
    GPIO_SetBits(GPIOB,GPIO_Pin_12);            
    
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_13 | GPIO_Pin_14 | GPIO_Pin_15;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_PP; 
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_Init(GPIOB, &GPIO_InitStructure);
 	GPIO_SetBits(GPIOB,GPIO_Pin_13|GPIO_Pin_14|GPIO_Pin_15);

    //RST pin
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_5;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP; 
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init(GPIOC, &GPIO_InitStructure);
    GPIO_SetBits(GPIOC,GPIO_Pin_5);
    
    //setup SPI2
    SPI_InitStructure.SPI_Direction = SPI_Direction_2Lines_FullDuplex;  
    SPI_InitStructure.SPI_Mode = SPI_Mode_Master;       
    SPI_InitStructure.SPI_DataSize = SPI_DataSize_8b;       
    SPI_InitStructure.SPI_CPOL = SPI_CPOL_Low;      
    SPI_InitStructure.SPI_CPHA = SPI_CPHA_1Edge;    
    SPI_InitStructure.SPI_NSS = SPI_NSS_Soft;       
    SPI_InitStructure.SPI_BaudRatePrescaler = SPI_BaudRatePrescaler_2;        
    SPI_InitStructure.SPI_FirstBit = SPI_FirstBit_MSB;  
    SPI_InitStructure.SPI_CRCPolynomial = 7;    
    SPI_Init(SPI2, &SPI_InitStructure);  

    SPI_Cmd(SPI2, ENABLE); 
    
    SPI2_ReadWriteByte(0xff);
}

void ENC28J60_Reset(void)
{

    ENC28J60_SPI2_Init(); //re-init SPI2
    ENC28J60_RST_CLEAR(); //reset ENC28J60      
    ENC28J60_delayms(10);    
    ENC28J60_RST_SET(); //finish reset              
    ENC28J60_delayms(10);    
}

//Read ENC28J60 register
//op: command
//addr: register address
//return: read out data
u8 ENC28J60_Read_Op(u8 op,u8 addr)
{
    u8 dat=0;    

    ENC28J60_SELECT();   
    ENC28J60_cs_delayms();    
    dat=op|(addr&ADDR_MASK);
    SPI2_ReadWriteByte(dat);
    dat=SPI2_ReadWriteByte(0xFF);
    //datasheet p.29, read two times to get MAC/MII register value
    if(addr&0x80)dat=SPI2_ReadWriteByte(0xFF);
    ENC28J60_cs_delayms();    
  ENC28J60_NO_SELECT();   
    return dat;
}
//Write ENC28J60 register
//op: command
//addr: register address
//data: parameter to write
void ENC28J60_Write_Op(u8 op,u8 addr,u8 data)
{
    u8 dat = 0;     
    ENC28J60_SELECT();             
    ENC28J60_cs_delayms();    
    dat=op|(addr&ADDR_MASK);
    SPI2_ReadWriteByte(dat);      
    SPI2_ReadWriteByte(data);
      ENC28J60_cs_delayms();    
    ENC28J60_NO_SELECT();
}
//Read Rx buffer data from ENC28J60
//len: data length to read
//data: pointer to store data
void ENC28J60_Read_Buf(u32 len,u8* data)
{
    ENC28J60_SELECT();           
    ENC28J60_cs_delayms();    
    SPI2_ReadWriteByte(ENC28J60_READ_BUF_MEM);
    while(len--) {
        *data++=(u8)SPI2_ReadWriteByte(0);
    }
    ENC28J60_cs_delayms();    
    ENC28J60_NO_SELECT();
}
//Write data to send via ENC28J60
//len: data length to send
//data: data pointer
void ENC28J60_Write_Buf(u32 len,u8* data)
{
    ENC28J60_SELECT();             
    ENC28J60_cs_delayms();    
    SPI2_ReadWriteByte(ENC28J60_WRITE_BUF_MEM);      
    while(len--)
    {
        SPI2_ReadWriteByte(*data++);
    }
    ENC28J60_cs_delayms();    
    ENC28J60_NO_SELECT();
}
//Setup ENC28J60 register bank
//ban: Bank to be setup
void ENC28J60_Set_Bank(u8 bank)
{                                   
    if((bank&BANK_MASK)!=ENC28J60BANK)
    {                 
        ENC28J60_Write_Op(ENC28J60_BIT_FIELD_CLR,ECON1,(ECON1_BSEL1|ECON1_BSEL0));
        ENC28J60_Write_Op(ENC28J60_BIT_FIELD_SET,ECON1,(bank&BANK_MASK)>>5);
        ENC28J60BANK=(bank&BANK_MASK);
    }
}
//Read ENC28J60 register
//addr: register address
//return: read out value
u8 ENC28J60_Read(u8 addr)
{                         
    ENC28J60_Set_Bank(addr);//select bank        
    return ENC28J60_Read_Op(ENC28J60_READ_CTRL_REG,addr);
}
//Write ENC28J60 register
//addr: register address     
void ENC28J60_Write(u8 addr,u8 data)
{                     
    ENC28J60_Set_Bank(addr);         
    ENC28J60_Write_Op(ENC28J60_WRITE_CTRL_REG,addr,data);
}
//Write into PHY register of ENC28J60
//addr: register address
//data: parameter written into register  
void ENC28J60_PHY_Write(u8 addr,u32 data)
{
    u16 retry=0;
    ENC28J60_Write(MIREGADR,addr);  
    ENC28J60_Write(MIWRL,data);     
    ENC28J60_Write(MIWRH,data>>8);         
    while((ENC28J60_Read(MISTAT)&MISTAT_BUSY)&&retry<0XFFF)retry++;//wait until PHY writing finish  
}
//Setup ENC28J60
//macaddr: assigned MAC address
//return: 0=success, 1=failed
u8 ENC28J60_Init(u8* macaddr)
{       
    u16 retry=0;          
    ENC28J60_Reset();
    ENC28J60_Write_Op(ENC28J60_SOFT_RESET,0,ENC28J60_SOFT_RESET); //software reset
    while(!(ENC28J60_Read(ESTAT)&ESTAT_CLKRDY)&&retry<500)  //wait until clock is stable
    {
        retry++;
        ENC28J60_delayms(1);
    };
    if(retry>=500)return 1;//initialization failed
    //set Rx buffer address with 8k capacity
    NextPacketPtr=RXSTART_INIT;

    //初始化接收缓冲区，设置接收起始地址
    ENC28J60_Write(ERXSTL,RXSTART_INIT&0xFF);   
    ENC28J60_Write(ERXSTH,RXSTART_INIT>>8);   
      
    //设置接收读指针指向地址
    ENC28J60_Write(ERXRDPTL, RXSTART_INIT &0xFF);
    ENC28J60_Write(ERXRDPTH, RXSTART_INIT>>8);
    
    //设置接收缓冲区的末尾地址
    ENC28J60_Write(ERXNDL,RXSTOP_INIT&0xFF);
    ENC28J60_Write(ERXNDH,RXSTOP_INIT>>8);

    //设置发送缓冲区的起始地址
    ENC28J60_Write(ETXSTL,TXSTART_INIT&0xFF);
    ENC28J60_Write(ETXSTH,TXSTART_INIT>>8);
    //setup "eno of tx" byte
    ENC28J60_Write(ETXNDL,TXSTOP_INIT&0xFF);
    ENC28J60_Write(ETXNDH,TXSTOP_INIT>>8);
 

    ENC28J60_Write(ERXFCON, ERXFCON_UCEN|ERXFCON_CRCEN|ERXFCON_PMEN);

    ENC28J60_Write(EPMM0,0x3f); 
    ENC28J60_Write(EPMM1,0x30);
    ENC28J60_Write(EPMCSL,0xf9);
    ENC28J60_Write(EPMCSH,0xf7);
    
    //MAC接收使能，下行程序段表示使能MAC接收，使能IEEE流量控制
    ENC28J60_Write(MACON1,MACON1_MARXEN|MACON1_TXPAUS|MACON1_RXPAUS);
    // bring MAC out of reset
    ENC28J60_Write(MACON2,0x00);    //MACON2清零，让MAC退出复位状态
    // enable automatic padding to 60bytes and CRC operations
    ENC28J60_Write_Op(ENC28J60_BIT_FIELD_SET,MACON3,MACON3_PADCFG0|MACON3_TXCRCEN|MACON3_FRMLNEN|MACON3_FULDPX);
    // set inter-frame gap (non-back-to-back)
    ENC28J60_Write(MAIPGL,0x12);
    ENC28J60_Write(MAIPGH,0x0C);
    // set inter-frame gap (back-to-back)
    ENC28J60_Write(MABBIPG,0x15);
    // Set the maximum packet size which the controller will accept
    // Do not send packets longer than MAX_FRAMELEN:
    ENC28J60_Write(MAMXFLL,MAX_FRAMELEN&0xFF);  
    ENC28J60_Write(MAMXFLH,MAX_FRAMELEN>>8);

    // do bank 3 stuff
    // write MAC address
    // NOTE: MAC address in ENC28J60 is byte-backward
    ENC28J60_Write(MAADR5,macaddr[0]);  
    ENC28J60_Write(MAADR4,macaddr[1]);
    ENC28J60_Write(MAADR3,macaddr[2]);
    ENC28J60_Write(MAADR2,macaddr[3]);
    ENC28J60_Write(MAADR1,macaddr[4]);
    ENC28J60_Write(MAADR0,macaddr[5]);

    //setup PHY as Duplex
    ENC28J60_PHY_Write(PHCON1,PHCON1_PDPXMD);    
    // no loopback of transmitted frames     禁止环回
    //HDLDIS：PHY 半双工环回禁止位
    ENC28J60_PHY_Write(PHCON2,PHCON2_HDLDIS);
    // switch to bank 0  
    ENC28J60_Set_Bank(ECON1);
    // enable interrutps
    ENC28J60_Write_Op(ENC28J60_BIT_FIELD_SET,EIE,EIE_INTIE|EIE_PKTIE);
    // enable packet reception
    ENC28J60_Write_Op(ENC28J60_BIT_FIELD_SET,ECON1,ECON1_RXEN);
    if(ENC28J60_Read(MAADR5)== macaddr[0]) {
        ENC28J60_delayms(10);
        return 0;//initialization success
    }
    if(ENC28J60_Read(MAADR4)== macaddr[1]) {
        ENC28J60_delayms(10);
        return 0;//initialization success
    }
     if(ENC28J60_Read(MAADR3)== macaddr[2]) {
        ENC28J60_delayms(10);
        return 0;//initialization success
    }
     if(ENC28J60_Read(MAADR2)== macaddr[3]) {
        ENC28J60_delayms(10);
        return 0;//initialization success
    }
     if(ENC28J60_Read(MAADR1)== macaddr[4]) {
        ENC28J60_delayms(10);
        return 0;//initialization success
    }
     if(ENC28J60_Read(MAADR0)== macaddr[5]) {
        ENC28J60_delayms(10);
        return 0;//initialization success
    }
    
    return -1;
}
//Read EREVID
u8 ENC28J60_Get_EREVID(void)
{
    return ENC28J60_Read(EREVID);
}



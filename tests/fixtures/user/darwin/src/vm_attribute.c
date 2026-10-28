/* Native oracle for vm_user.c/vm_map.c cache-attribute behavior. */
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_attributes.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
 mach_vm_size_t page=(mach_vm_size_t)getpagesize();
 mach_vm_address_t a=0; kern_return_t r=mach_vm_allocate(mach_task_self(),&a,8*page,VM_FLAGS_ANYWHERE);if(r)return 1;
 if(mach_vm_deallocate(mach_task_self(),a+4*page,page))return 2;
 *(volatile uint32_t*)(uintptr_t)a=0x12345678;
 int values[]={-1,0,1,2,6,7,8,9,10,11};
 for(int i=0;i<10;i++){int v=values[i];r=mach_vm_machine_attribute(mach_task_self(),a+1,4,MATTR_CACHE,&v);printf("value=%d result=%d out=%d\n",values[i],r,v);}
 struct {uint64_t a,n;int attr;} rows[]={ {a,4,0},{a,4,2},{a,4,3},{a,0,2},{UINT64_MAX,0,9},{UINT64_MAX,1,1},{UINT64_MAX-1,8,1},{0,4,1},{0x1000,4,1},{a+4*page,4,1}};
 for(int i=0;i<10;i++){int v=6;r=mach_vm_machine_attribute(mach_task_self(),rows[i].a,rows[i].n,rows[i].attr,&v);printf("row=%d result=%d out=%d\n",i,r,v);}
 return mach_vm_deallocate(mach_task_self(),a,8*page)!=0;
}

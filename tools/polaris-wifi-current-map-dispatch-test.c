/* SOFTWARE composition of six independent copied-IO contexts. Only generic
 * GCD/relay code executes; original PE and every firmware/AT/FP leaf are DATA
 * or explicit peers. This does not execute the whole power preparation body. */
#define POLARIS_CURRENT_MAP_FIXTURE_ONLY 1
#include "polaris-wifi-current-map-test.c"
static struct pcmp_route routes[PCMP_PARENT_CONTEXTS];
static unsigned active_route;
static int dispatch_relay(void*o,struct efi_system*sys,struct pgcd_map*m,void*data)
{
    assert(!o&&sys==s);unsigned n=99,k=99;
    assert(pcmp_select(routes,PCMP_PARENT_CONTEXTS,m,data,&n,&k)&&n==active_route);
    cur=&routes[n].frames[k];
    return pcmp_route_read(&routes[n],k,&current_input,&original_io,m,data,current_fixture_page);
}
static void dispatch_fixture(void)
{
    fixture_image_bytes=0xf00000;setup_current(0);memset(arena+0x400000,0,0x600000);
    for(unsigned n=0;n<PCMP_PARENT_CONTEXTS;n++){
        struct pgcd_result*source=(void*)(arena+0x400000+0x10000*n);
        struct pgcd_context*context=(void*)(arena+0x460000+0x1000*n);
        struct pgcd_lifetime*life=(void*)((uint8_t*)context+0x200);
        struct pcmp_result*frames=(void*)(arena+0x500000+2*sizeof(*frames)*n);
        assert(pgcd_bind(source,self));source->self_owner_address=(uintptr_t)self;
        routes[n]=(struct pcmp_route){context,source,life,frames,n==0?PCMP_QUERY_PAIR:n==5?PCMP_CLIENT_OPEN:PCMP_PREPARATION_PAIR,0};
    }
    struct pgcd_context*final=routes[0].context;
    *final=(struct pgcd_context){.io=original_io,.record=routes[0].source,.ticket=routes[0].ticket,.stage=2};
    final->io.map=dispatch_relay;
    /* Same IO inheritance used by pwsp_piece and pwrcl_run_body, with a
     * different exact source/ticket for every constructor. No opened/spent,
     * query, finished or retirement state is manufactured. */
    for(unsigned n=1;n<PCMP_PARENT_CONTEXTS;n++){
        struct pgcd_context*early_context=routes[n].context;
        early_context->io=final->io;early_context->record=routes[n].source;
        early_context->ticket=routes[n].ticket;early_context->stage=2;
    }
}
static void activate(unsigned n)
{active_route=n;c=routes[n].context;r=routes[n].source;ticket=routes[n].ticket;cur=routes[n].frames;queries=0;}
#ifndef POLARIS_CURRENT_MAP_DISPATCH_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x1001000));
    assert(!posix_memalign((void**)&payload_data,4096,4096)&&!posix_memalign((void**)&log_data,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");
    assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned checks=0;
    dispatch_fixture();
    /* Four RO pairs, the private client's one opening, then the final query
     * pair: the real parent needs eleven existing private maps, not two. */
    for(unsigned pass=0;pass<PCMP_PARENT_CONTEXTS;pass++){
        unsigned n=pass<5?pass+1:0;activate(n);
        if(n){
            assert(&r->map[0]!=&routes[0].source->map[0]&&&r->map[0]!=&routes[0].source->map[1]);checks++;
            assert(pgcd_open(c)&&c->opened==1&&!c->finished&&r->phase==1&&ticket->spent==1);
            if(n<5)assert(pgcd_map_read(c,1)&&!c->finished&&!r->pre_mask&&!r->post_mask&&r->phase==1);
            else{unsigned i=99,k=99;assert(!pcmp_select(routes,6,&r->map[1],r->maps[1],&i,&k));checks++;}
            assert(!routes[0].source->attempted&&!routes[0].ticket->spent&&!routes[0].context->opened);
        }else{
            for(unsigned k=0;k<4;k++){const struct pgcd_observation*observation=0;assert(pgcd_query_page(c,pgcd_pages[k],&observation));}
            assert(pgcd_finish(c)&&c->finished&&r->phase==2&&queries==8);
        }
        for(unsigned k=0;k<(n==5?1u:2u);k++){
            const struct pcmp_result*a=&routes[n].frames[k];
            assert(a->complete&&!a->unknown&&!a->error&&a->input.context==c&&a->context_before.record==r&&
                a->context_before.ticket==ticket&&a->path==routes[n].path&&a->slot==k&&a->map_issued==1&&a->map_returned==1);
            assert(a->source_before.before.cpu.ticks==r->before.cpu.ticks);checks++;
        }
    }
    assert(leaf_maps==11&&pwmc_zero(&routes[5].frames[1],sizeof(struct pcmp_result)));checks++;
    FILE*out=fopen(argv[2],"wb");assert(out);
    for(unsigned n=0;n<6;n++)assert(fwrite(routes[n].frames,sizeof(struct pcmp_result),2,out)==2);
    assert(!fclose(out));
    /* Complete selection matrix rejects foreign buffers, interior map
     * pointers and the unimplemented client closing slot before any leaf. */
    unsigned before=leaf_maps;
    for(unsigned n=0;n<6;n++)for(unsigned k=0;k<2;k++)for(unsigned peer=0;peer<6;peer++){
        unsigned i=99,j=99;int ok=pcmp_select(routes,6,&routes[n].source->map[k],routes[peer].source->maps[k],&i,&j);
        assert(ok==(peer==n&&!(n==5&&k)));
        if(ok)assert(i==n&&j==k);checks++;
    }
    for(unsigned n=0;n<6;n++){
        unsigned i=99,j=99;struct pcmp_route old=routes[n];
        assert(!pcmp_select(routes,5,&old.source->map[0],old.source->maps[0],&i,&j));checks++;
        assert(!pcmp_select(routes,6,(void*)((uintptr_t)&old.source->map[0]+1),old.source->maps[0],&i,&j));checks++;
        routes[n].source=routes[(n+1)%6].source;assert(!pcmp_select(routes,6,&old.source->map[0],old.source->maps[0],&i,&j));routes[n]=old;checks++;
        activate(n);struct pgcd_context saved=*c;c->record=(void*)8;
        assert(!pcmp_route_read(&routes[n],0,&current_input,&original_io,&r->map[0],r->maps[0],current_page));*c=saved;checks++;
        c->ticket=(void*)8;assert(!pcmp_route_read(&routes[n],0,&current_input,&original_io,&r->map[0],r->maps[0],current_page));*c=saved;checks++;
        assert(!pcmp_route_read(&routes[n],0,&current_input,&original_io,&r->map[0],r->maps[0],current_page));checks++;
    }
    unsigned i=99,j=99;assert(!pcmp_select(routes,6,(void*)8,(void*)8,&i,&j)&&leaf_maps==before);checks++;
    /* Fresh real generic opens feed each actual RO close shape. Mutating a
     * retained opening, lifetime or the query/finished state cannot turn it
     * into another mode or renew its original opening. */
    for(unsigned n=1;n<5;n++)for(unsigned bad=0;bad<10;bad++){
        dispatch_fixture();activate(n);assert(pgcd_open(c));unsigned calls=leaf_maps;
        switch(bad){case 0:routes[n].frames[0].digest[0]^=1;break;case 1:routes[n].frames[0].source_before.before.cpu.ticks++;break;
        case 2:ticket->result++;break;case 3:r->before.cpu.ticks++;break;case 4:c->finished=1;break;
        case 5:r->pre_mask=15;break;case 6:r->post_mask=15;break;case 7:r->prestart_count=1;break;
        case 8:r->query[0][0].issued=1;break;case 9:routes[n].path=PCMP_QUERY_PAIR;break;default:assert(0);}
        /* pgcd_map_read runs its original guard before the callback. */
        assert(!pgcd_map_read(c,1)&&leaf_maps==calls);checks++;
    }
    printf("{\"passed\":true,\"checks\":%u,\"contexts\":6,\"existing_private_maps\":11,\"stored_frames\":12,\"frame_bytes\":%zu,\"fault_bytes\":%zu,\"SOFTWARE_only\":true,\"whole_power_constructor_executed\":false}\n",checks,sizeof(struct pcmp_result),sizeof(struct pcmp_route_fault));
    free(original);free(arena);free(payload_data);free(log_data);return 0;
}
#endif

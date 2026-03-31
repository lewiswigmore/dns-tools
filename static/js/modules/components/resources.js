import { KNOWLEDGE_BASE } from '../data/index.js';

export function ResourcesPage() {
    return {
      conceptModal: false,
      currentConcept: '',
      conceptContent: '',
      loadingConcept: false,
      conceptError: '',
      conceptAnimations: {},
      knowledgeBase: KNOWLEDGE_BASE,
      complexityFilter: 'All',
      categoryFilter: 'All',
      searchQuery: '',
      currentPage: 1,
      pageSize: 20,
      pageSizeOptions: [10, 20, 50],
      
      get filteredKnowledgeBase() {
        let items = this.knowledgeBase;

        // Filter by Search Query
        if (this.searchQuery) {
            const query = this.searchQuery.toLowerCase();
            items = items.filter(item => 
                item.title.toLowerCase().includes(query) || 
                item.summary.toLowerCase().includes(query) ||
                item.tags.some(tag => tag.toLowerCase().includes(query))
            );
        }

        // Filter by Category (from URL or selection)
        if (this.categoryFilter !== 'All') {
            if (this.categoryFilter === 'Security') {
                // "Knowledge Base" view - Security focused
                items = items.filter(item => 
                    item.tags.includes('Threat Intel') || 
                    item.tags.includes('Cloud Security') || 
                    item.tags.includes('Malware') ||
                    item.tags.includes('Security')
                );
            } else {
                // Generic tag filter
                items = items.filter(item => item.tags.includes(this.categoryFilter));
            }
        }

        // Filter by Complexity (dropdown)
        if (this.complexityFilter !== 'All') {
            items = items.filter(item => item.complexity === this.complexityFilter);
        }
        
        return items;
      },

      get totalPages() {
        return Math.max(1, Math.ceil(this.filteredKnowledgeBase.length / this.pageSize));
      },

      get paginatedKnowledgeBase() {
        // Clamp to a valid page whenever filters or search shrink the result set.
        if (this.currentPage > this.totalPages) {
          this.currentPage = this.totalPages;
        }
        if (this.currentPage < 1) {
          this.currentPage = 1;
        }

        const start = (this.currentPage - 1) * this.pageSize;
        const end = start + this.pageSize;
        return this.filteredKnowledgeBase.slice(start, end);
      },

      get pageStartItem() {
        if (this.filteredKnowledgeBase.length === 0) return 0;
        return (this.currentPage - 1) * this.pageSize + 1;
      },

      get pageEndItem() {
        return Math.min(this.currentPage * this.pageSize, this.filteredKnowledgeBase.length);
      },

      get pageTitle() {
          return this.categoryFilter === 'Security' ? 'Knowledge Base' : 'Content Library';
      },

      resetPage() {
        this.currentPage = 1;
        this.updateUrlState();
      },

      goToPage(page) {
        this.currentPage = Math.max(1, Math.min(page, this.totalPages));
        this.updateUrlState();
      },

      goToFirstPage() {
        this.goToPage(1);
      },

      goToLastPage() {
        this.goToPage(this.totalPages);
      },

      setPageSize(size) {
        this.pageSize = size;
        this.currentPage = 1;
        this.updateUrlState();
      },

      updateUrlState() {
        const url = new URL(window.location.href);
        const params = url.searchParams;

        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        else params.delete('q');

        if (this.complexityFilter !== 'All') params.set('complexity', this.complexityFilter);
        else params.delete('complexity');

        if (this.categoryFilter !== 'All') params.set('category', this.categoryFilter);
        else params.delete('category');

        params.set('page', String(this.currentPage));
        params.set('size', String(this.pageSize));

        history.replaceState({}, '', `${url.pathname}?${params.toString()}`);
      },

      previousPage() {
        this.goToPage(this.currentPage - 1);
      },

      nextPage() {
        this.goToPage(this.currentPage + 1);
      },

      init() {
        // Initialize random pulse animations for DNS concepts
        this.initRandomPulseAnimations();

        // Check for params in URL
        const urlParams = new URLSearchParams(window.location.search);
        
        const category = urlParams.get('category');
        if (category) {
            this.categoryFilter = category;
          this.resetPage();
        }

        const q = urlParams.get('q');
        if (q) this.searchQuery = q;

        const complexity = urlParams.get('complexity');
        if (complexity && ['All', 'Beginner', 'Intermediate', 'Advanced'].includes(complexity)) {
          this.complexityFilter = complexity;
        }

        const size = Number(urlParams.get('size'));
        if (this.pageSizeOptions.includes(size)) {
          this.pageSize = size;
        }

        const page = Number(urlParams.get('page'));
        if (Number.isInteger(page) && page > 0) {
          this.currentPage = page;
        }

        const concept = urlParams.get('concept');
        if (concept) {
            // Wait a tick for Alpine to initialize
            this.$nextTick(() => {
                this.showConcept(decodeURIComponent(concept));
            });
        }

        this.updateUrlState();
      },
      
      initRandomPulseAnimations() {
        const concepts = [
          'A Record', 'AAAA Record', 'CNAME Record', 'MX Record', 
          'TXT Record', 'NS Record', 'PTR Record', 'SRV Record', 'CAA Record',
          'SPF', 'DKIM', 'DMARC'
        ];
        
        // Randomly select 3-4 concepts to pulse
        const numToPulse = Math.floor(Math.random() * 2) + 3; // 3 or 4 concepts
        const shuffled = concepts.sort(() => 0.5 - Math.random());
        const selectedConcepts = shuffled.slice(0, numToPulse);
        
        // Initialize all concepts as not pulsing
        concepts.forEach(concept => {
          this.conceptAnimations[concept] = false;
        });
        
        // Add staggered pulse animations
        selectedConcepts.forEach((concept, index) => {
          setTimeout(() => {
            this.conceptAnimations[concept] = true;
            
            // Stop pulsing after user has been on page for a while (15 seconds)
            setTimeout(() => {
              this.conceptAnimations[concept] = false;
            }, 15000);
          }, index * 800); // Stagger the start times by 800ms
        });
      },
      
      showConcept(conceptName) {
        this.currentConcept = conceptName;
        this.conceptModal = true;
        this.loadConcept(conceptName);
      },
      
      closeConcept() {
        this.conceptModal = false;
        this.conceptContent = '';
        this.conceptError = '';
        this.currentConcept = '';
      },
      
      async loadConcept(conceptName) {
        this.loadingConcept = true;
        this.conceptError = '';
        this.conceptContent = '';
        
        try {
          // Check if it's in our Knowledge Base
          const kbItem = this.knowledgeBase.find(item => item.title === conceptName);
          
          if (kbItem) {
             await new Promise(resolve => setTimeout(resolve, 300)); // Small UI delay
             this.conceptContent = kbItem.content;
          } else {
             this.conceptError = 'Concept not found.';
          }
          
        } catch (error) {
          this.conceptError = 'Failed to load detailed explanation. Please try again.';
        } finally {
          this.loadingConcept = false;
        }
      }
    };
  };
